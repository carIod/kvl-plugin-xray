#!/bin/sh

VERSION=1.0.2
PR_NAME="Xray-core"
PR_TYPE="Прозрачный прокси"
#DESCRIPTION="Xray (vless/ss)"
TEMPLATES="/opt/apps/kvl/bin/plugins/templates"
PROC=xray
CONF="/opt/etc/kvl/xray-conf.json"
ARGS="run -c $CONF"
#========================================================================================================================================
# Передаваемые параметры работы плагина ( метод на текущий момент может быть tproxy - Прозрачный прокси и wg - POINT-TO-POINT тунель)
METOD=tproxy
#Как пересылать TCP пакеты из iptables в модуль через dnat или tproxy
TCP_WAY=tproxy
LOCAL_PORT=1181
#============================================= тестирование соединения ==================================================================
PING_COUNT=3
PING_TIMEOUT=1
TEST_PORT=1888
URL_TEST="http://cachefly.cachefly.net/1mb.test"
URL_TEST_SIZE=1048576
#========================================================================================================================================

ansi_red="\033[1;31m";
ansi_white="\033[1;37m";
ansi_green="\033[1;32m";
ansi_yellow="\033[1;33m";
ansi_blue="\033[36m";
#ansi_bell="\007";
#ansi_blink="\033[5m";
#ansi_rev="\033[7m";
#ansi_ul="\033[4m";
ansi_std="\033[m";
# путь к корневым сертификатам (должен быть установлен пакет opkg install ca-certificates )
export SSL_CERT_DIR=/opt/etc/ssl/certs

if [ -t 1 ]; then
  INTERACTIVE=1
else
  INTERACTIVE=0
fi
get_pid() {
  pgrep -f "$PROC.*-c $CONF" 2>/dev/null || echo ""
  #ps | grep "$PROC" | grep -F -- "-c $CONF" | grep -v grep | awk '{print $1}' # for POSIX
}
# Вычисляем текущую ширину экрана для печати линий определенной ширины
length=$(stty size 2>/dev/null | cut -d' ' -f2)
[ -n "${length}" ] && [ "${length}" -gt 80 ] && LENGTH=$((length*2/3)) || LENGTH=68
# Печатает линию в зависимости от ширины stty
print_line() {
	len=$((LENGTH))
	printf "%${len}s\n" | tr " " "-"
}
# Получение ip адреса хоста
resolve_ip() {
    local host="$1"
    local dns_server="127.0.0.1"
    nslookup "$host" "$dns_server" 2>/dev/null | \
        awk '/^Address [0-9]+: / && $3 !~ /^127\./ && $3 !~ /:/ { print $3; exit }'
}

# ------------------------------------------------------------------------------------------
#	 Читаем значение переменной из ввода данных в цикле
#	 $1 - заголовок для запроса
#	 $2 - переменная в которой возвращается результат
#	 $3 - тип вводимого значения #		 (digit) - цифра  (password) - пароль без показа вводимых символов
# ------------------------------------------------------------------------------------------
read_value() {
	header="$(echo "${1}" | tr -d '?')"
	type="${3}"

	while true; do
		echo -en "${header}${ansi_std} [Q-выход]  "
		if [ "${type}" = 'password' ]; then read -rs value; else read -r value; fi
		if [ -z "${value}" ]; then
				echo
				print_line
				echo -e "${ansi_red}Данные не должны быть пустыми!"
				echo -e "${ansi_green}Попробуйте ввести значение снова...${ansi_std}"
				print_line
		elif echo "${value}" | grep -qiE '^Q$' ; then
				eval "${2}=q"
				break
		elif [ "${type}" = 'digit' ] && ! echo "${value}" | grep -qE '^[[:digit:]]{1,6}$'; then
				echo
				print_line
				echo -e "${ansi_red}Введенные данные должны быть цифрами!"
				echo -e "${ansi_green}Попробуйте ввести значение снова...${ansi_std}"
				print_line
		elif [ "${type}" = 'password' ] && ! echo "${value}" | grep -qE '^[a-zA-Z0-9]{8,1024}$' ; then
				echo
				print_line
				echo -e "${ansi_green}Пароль должен содержать минимум 8 знаков и"
				echo -e "${ansi_green}ТОЛЬКО буквы и ЦИФРЫ, ${ansi_red}без каких-либо спец символов!${ansi_std}"
				echo -e "${ansi_red}Попробуйте ввести его снова...${ansi_std}"
				print_line
		else
				eval "${2}=\"\$value\""
				break
		fi
	done
}

url_decode() {
  local encoded="${1//+/ }"
  printf '%b' "${encoded//%/\\x}"
}

get_param() {
  local query="$1"
  local key="$2"
  local default="${3:-}"  # третий аргумент — значение по умолчанию
  local val
  val=$(echo "$query" | awk -F'&' -v key="$key" '{
    for (i=1; i<=NF; i++) {
      if ($i ~ "^" key "=") {
        print substr($i, length(key)+2)
        exit
      }
    }
  }')
  if [ -z "$val" ]; then
    echo "$default"
  else
    url_decode "$val"
  fi
}

read_fake_sni() {
    local disguise
    if [ "$special" = "fake" ]; then
      disguise="y"
    else  
      echo -e "${ansi_white}🔐 Настраиваем маскировку трафика для VLESS-соединения (tls или xtls).${ansi_std}"
      echo -e ""
      echo "Производится попытка изменить вид трафика, чтобы он выглядел как стандартный HTTPS-запрос."
      echo "Эта функция предназначена для изучения сетевых протоколов и тестирования маскировки трафика."
      echo "Эффективность зависит от особенностей сети и настроек сервера, результаты могут быть различными."
      echo ""
      read_value "${ansi_yellow}🕵️ Хотите попробовать маскировку трафика? (y/n)" disguise || disguise="y"
    fi  
    case "$disguise" in
        [Yy]*)
            echo ""
            echo "ℹ️ SNI (Server Name Indication) — это имя, которое клиент показывает серверу при установке защищённого соединения."
            echo "Можно указать любой популярный домен для тестирования работы SNI в сетевых соединениях."
            echo ""
            echo "⚠️ ВАЖНО: для этой маскировки мы включаем опцию 'allowInsecure' в настройках TLS."
            echo "Это позволяет соединению принимать неподтверждённые сертификаты, которые не проверены центром сертификации."
            echo "Риск: злоумышленник теоретически может попытаться организовать атаку 'человек посередине' (MITM), перехватив трафик."
            echo "Однако если вы используете HTTPS-сайты, их содержимое остаётся зашифрованным и недоступно для посторонних."
            echo "Если вы подключаетесь к бесплатному серверу, для тестирования, этот риск фактически присутствует всегда, так что дополнительной опасности не возникает."
            echo ""
            read_value "${ansi_green} Введите SNI для тестирования (например, имя сервера)" sni
            echo ""
            if [ -z "$sni" ] || [[ "$sni" =~ ^[Qq]$ ]]; then
              exit 1
            fi  
            special="fake"
            ;;
        [Qq]*) 
            exit 1 
            ;;   
        *)
            special=""
            ;;
    esac
}

read_fake_host() {
    local disguise
    if [ "$special" = "fake" ]; then
      disguise="y"
    else  
      disguise="n"
    fi  
    case "$disguise" in
        [Yy]*)
            echo ""
            echo "ℹ️ Host-заголовок — это часть запроса, которая указывает, к какому серверу вы обращаетесь через WebSocket или HTTP."
            echo "Указав тот же домен, что и в SNI, вы проверяете согласованность настроек и поведение сервера при совпадающих параметрах."
            echo ""
            read_value "${ansi_green} Введите Host-заголовок для тестирования (например, имя сервера)" header_host
            if [ -z "$sni" ] || [[ "$sni" =~ ^[Qq]$ ]]; then
              exit 1
            fi
            special="fake"
            ;;
        [Qq]*) 
            exit 1 
            ;;   
        *)
            special=""
            ;;
    esac
}

read_allowInsecure() {
  read_value "${ansi_yellow}🕵️ Игнорировать сертификат сервера?, но есть риски MITM (y/n)" disguise || disguise="n"
  case "$disguise" in
    [Yy]*) allowInsecure="true" ;;
    [Qq]*) exit 1 ;;   
    *) allowInsecure="false" ;;
  esac
}

parse_vless(){
  # Удаляем префикс vless://
  local core="${1#vless://}"
  local local_port="$2"
  local cfg_file="$3"

  # Проверяем наличие # в строке
  if [[ "$core" == *"#"* ]]; then
    desc="${core#*#}"
    core="${core%%#*}"
  else
    desc=""
  fi
  # Проверяем, что строка содержит @
  if [[ "$core" != *"@"* ]]; then
    echo -e "${ansi_red}Ошибка: некорректный формат строки (отсутствует @)${ansi_std}" >&2
    return 1
  fi
  # Извлекаем UUID, host и port
  uuid="${core%%@*}"
  # Проверяем формат UUID
  if [[ ! "$uuid" =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]]; then
    echo -e "${ansi_yellow}Предупреждение: UUID не похоже на стандартный${ansi_std}" >&2
  fi
  # Извлекаем подстроку host:port
  hostport="${core#*@}"
  hostport="${hostport%%\?*}"
  if [[ ! "$hostport" =~ ^[^:]+:[0-9]+$ ]]; then
    echo -e "${ansi_red}Ошибка: некорректный формат host:port${ansi_std}" >&2
    return 1
  fi  
  if [[ "$hostport" != *:* || "$hostport" == *:*:* ]]; then
    echo -e "${ansi_red}Ошибка: некорректный формат host:port${ansi_std}" >&2
  fi
  host="${hostport%:*}"
  port="${hostport#*:}"
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo -e "${ansi_red}❌ Ошибка: неверный порт (должен быть 1-65535)${ansi_std}" >&2
    return 1
  fi
  # Извлекаем query (всё после ?)
  query="${core#*\?}"
  # Парсим основные параметры
  # Базовая безопасность передачи данных none, tls, xtls, reality, не может быть пустой строкой.
  security=$(get_param "$query" security)
  # Способ передачи tcp, kcp, ws, http, grpc
  network=$(get_param "$query" type)
  
  # Проверяем обязательные параметры
  if [ -z "$uuid" ] || [ -z "$host" ] || [ -z "$port" ] || [ -z "$security" ] || [ -z "$network" ]; then
    echo -e "${ansi_red}❌ Ошибка: обязательные поля отсутствуют в ссылке${ansi_std}"
    return 1
  fi
  # VLESS всегда none, не может быть пустой строкой  
  encryption=$(get_param "$query" encryption "none")
  # Путь к WebSocket Если не указан, по умолчанию используется значение /, но не может быть пустой строкой.
  path=$(get_param "$query" path "/")
  # Содержимое заголовка запроса WebSocket Host
  header_host=$(get_param "$query" host)
  # TLS SNI, соответствующий элементу в файле конфигурации serverName При пропуске используется повторно remote-host.
  sni=$(get_param "$query" sni)
  pub_key=$(get_param "$query" pbk)
  short_id=$(get_param "$query" sid)
  browser_fp=$(get_param "$query" fp)
  spiderX=$(get_param "$query" spx)
  alpn=$(get_param "$query" alpn)

  if [ -n "$alpn" ]; then
    alpn="\"$(echo "$alpn" | sed 's/,/", "/g')\""
  fi  

  special=""
  if [ "$security" = "tls" ] || [ "$security" = "xtls" ]; then
    [ -z "$sni" ] && read_fake_sni
    [ -z "$sni" ] && sni="$host"
  fi

  if [ "$network" = "ws"  ] || [ "$network" = "http" ]; then
    [ -z "$header_host" ] && read_fake_host
  fi

  local template="$TEMPLATES/vless-$network-$security"
  if [ -n "$special" ]; then
      template="$template-$special"
  fi
  template="$template.conf"
  echo -e "${ansi_blue}📁 Используем шаблон: $template${ansi_std}"
  local bak="${CONF}.bak"

  if [ ! -f "$template" ]; then
    echo -e "${ansi_red}❌ Шаблон не найден: $template${ansi_std}"
    return 1
  fi

  # Бэкап
  if [ -f "$CONF" ] && [ "$cfg_file" = "$CONF" ]; then
    mv "$CONF" "$bak"
    echo -e "${ansi_yellow}🔁 Старый конфиг сохранён как $bak${ansi_std}"
  fi
  sed \
    -e "s|__description__|$desc|g" \
    -e "s|__local_port__|$local_port|g" \
    -e "s|__UUID__|$uuid|g" \
    -e "s|__host__|$host|g" \
    -e "s|__port__|$port|g" \
    -e "s|__encryption__|$encryption|g" \
    -e "s|__network__|$network|g" \
    -e "s|__security__|$security|g" \
    -e "s|__sni__|$sni|g" \
    -e "s|__path__|$path|g" \
    -e "s|__header_host__|$header_host|g" \
    -e "s|__network__|$password|g" \
    -e "s|__browser_fp__|$browser_fp|g" \
    -e "s|__pub_key__|$pub_key|g" \
    -e "s|__short_id__|$short_id|g" \
    -e "s|__spiderX__|$spiderX|g" \
    -e "s|__alpn__|$alpn|g" \
  "$template" > "${cfg_file}"
  echo -e "${ansi_white}Конфигурационный файл настроен${ansi_std}"
}

parse_shadowsocks(){
    local url="${1#ss://}"
    local local_port="$2"
    local cfg_file="$3"
    local full decoded creds method password host port

    # 1. Если ссылка содержит @ — это SIP002
    if echo "$url" | grep -q '@'; then
        # Может быть ss://<base64(method:password)>@host:port или ss://method:password@host:port
        full="${url%%@*}"           # до @
        rest="${url#*@}"            # после @

        # Попробуем base64-декодировать до первого ':'
        decoded=$(echo "$full" | base64 -d 2>/dev/null)

        if echo "$decoded" | grep -q ':'; then
            creds="$decoded"
        else
            creds="$full" # не base64, используем как есть
        fi

        method="${creds%%:*}"
        password="${creds#*:}"

        host="${rest%%:*}"
        port="${rest#*:}"
        port="${port%%/*}"  # убрать параметры после порта

        # Проверим наличие query параметров
        if echo "$url" | grep -q '[?&]plugin='; then
          echo -e "${ansi_red}❌ Shadowsocks с plugin (например, obfs-local или v2ray-plugin) не поддерживается Xray${ansi_std}"
          return 1
        fi
    else
        # Это base64(full_uri) старый формат
        decoded=$(echo "$url" | sed 's/#.*//' | base64 -d 2>/dev/null)
        method="${decoded%%:*}"
        rest="${decoded#*:}"
        password="${rest%%@*}"
        rest="${rest#*@}"
        host="${rest%%:*}"
        port="${rest#*:}"
    fi
    # Проверка на пустые поля
    if [ -z "$method" ] || [ -z "$password" ] || [ -z "$host" ] || [ -z "$port" ]; then
        echo -e "${ansi_red}❌ Ошибка разбора Shadowsocks-ссылки: недостаточно параметров${ansi_std}"
        return 1
    fi
    
    local template="$TEMPLATES/ss-aead.conf"
    local bak="${CONF}.bak"

    if [ ! -f "$template" ]; then
        echo -e "${ansi_red}❌ Шаблон не найден: $template${ansi_std}"
        return 1
    fi
    echo "📁 Используем шаблон: $template"
    # Бэкап
    if [ -f "$CONF" ] && [ "$cfg_file" = "$CONF" ]; then
        mv "$CONF" "$bak"
        echo -e "${ansi_yellow}🔁 Старый конфиг сохранён как $bak${ansi_std}"
    fi
    sed \
        -e "s|__local_port__|$local_port|g" \
        -e "s|__host__|$host|g" \
        -e "s|__port__|$port|g" \
        -e "s|__method__|$method|g" \
        -e "s|__password__|$password|g" \
        "$template" > "${cfg_file}"
    echo -e "${ansi_white}Конфигурационный файл настроен${ansi_std}"

}

parse_trojan() {
  # Удаляем префикс trojan://
  local core="${1#trojan://}"
  local local_port="$2"
  local cfg_file="$3"

  # Проверяем наличие # в строке
  if [[ "$core" == *"#"* ]]; then
    desc="${core#*#}"
    core="${core%%#*}"
  else
    desc=""
  fi
  # Проверяем, что строка содержит @
  if [[ "$core" != *"@"* ]]; then
    echo -e "${ansi_red}Ошибка: некорректный формат строки (отсутствует @)${ansi_std}" >&2
    return 1
  fi
  # Извлекаем password, host и port
  password="${core%%@*}"
  # Проверяем password
  if [ -z "$password" ]; then
    echo -e "${ansi_red}Ошибка: password пустой${ansi_std}" >&2
    return 1
  fi
  # Извлекаем подстроку host:port
  hostport="${core#*@}"
  hostport="${hostport%%\?*}"
  if [[ ! "$hostport" =~ ^[^:]+:[0-9]+$ ]]; then
    echo -e "${ansi_red}Ошибка: некорректный формат host:port${ansi_std}" >&2
    return 1
  fi  
  if [[ "$hostport" != *:* || "$hostport" == *:*:* ]]; then
    echo -e "${ansi_red}Ошибка: некорректный формат host:port${ansi_std}" >&2
    return 1
  fi
  address="${hostport%:*}"
  port="${hostport#*:}"
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo -e "${ansi_red}❌ Ошибка: неверный порт (должен быть 1-65535)${ansi_std}" >&2
    return 1
  fi
  # Извлекаем query (всё после ?)
  query="${core#*\?}"
  # Парсим основные параметры
  # Базовая безопасность передачи данных tls, xtls, не может быть пустой строкой.
  security=$(get_param "$query" security)
  if [ -z "$security" ]; then
    security=tls
    echo -e "${ansi_yellow}Предупреждение: security не указан будет использоваться 'tls'${ansi_std}" >&2
  fi
  # Способ передачи tcp, ws, grpc, httpupgrade, h2
  network=$(get_param "$query" type)
  if [ -z "$network" ]; then
    network=tcp
    echo -e "${ansi_yellow}Предупреждение: network не указан будет использоваться 'tcp'${ansi_std}" >&2
  fi  
  # Проверяем обязательные параметры
  if [ -z "$password" ] || [ -z "$address" ] || [ -z "$port" ] || [ -z "$security" ] || [ -z "$network" ]; then
    echo -e "${ansi_red}❌ Ошибка: обязательные поля отсутствуют в ссылке${ansi_std}"
    return 1
  fi
  # Имя сервиса для gRPC
  serviceName=$(get_param "$query" serviceName)
  if [ "$network" = "grpc" ] && [ -z "$serviceName" ]; then
    echo -e "${ansi_red}Ошибка: Используется тип транспорта grpc, но serviceName не указан${ansi_std}" >&2
    return 1
  fi

  # Содержимое заголовка запроса WebSocket Host
  header_host=$(get_param "$query" host)

  # TLS SNI, соответствующий элементу в файле конфигурации serverName При пропуске используется повторно remote-host.
  sni=$(get_param "$query" sni)
 # Путь к WebSocket Если не указан, по умолчанию используется значение /, но не может быть пустой строкой.
  path=$(get_param "$query" path "/")

  alpn=$(get_param "$query" alpn)

  if [ -n "$alpn" ]; then
    alpn="\"$(echo "$alpn" | sed 's/,/", "/g')\""
  fi 

  special=""
  if [ "$security" = "tls" ] || [ "$security" = "xtls" ]; then
    [ -z "$sni" ] && read_fake_sni
    [ -z "$sni" ] && sni="$address"
  fi

  if [ "$network" = "ws"  ]; then
    [ -z "$header_host" ] && read_fake_host
  fi

  if [ -n "$special" ]; then
      allowInsecure=true
  else
    read_allowInsecure
  fi
  local template="$TEMPLATES/trojan-$security-$network.conf"
  echo -e "${ansi_blue}📁 Используем шаблон: $template${ansi_std}"
  local bak="${CONF}.bak"

  if [ ! -f "$template" ]; then
    echo -e "${ansi_red}❌ Шаблон не найден: $template${ansi_std}"
    return 1
  fi

  # Бэкап
  if [ -f "$CONF" ] && [ "$cfg_file" = "$CONF" ]; then
    mv "$CONF" "$bak"
    echo -e "${ansi_yellow}🔁 Старый конфиг сохранён как $bak${ansi_std}"
  fi
  sed \
    -e "s|__description__|$desc|g" \
    -e "s|__local_port__|$local_port|g" \
    -e "s|__password__|$password|g" \
    -e "s|__host__|$address|g" \
    -e "s|__port__|$port|g" \
    -e "s|__serviceName__|$serviceName|g" \
    -e "s|__network__|$network|g" \
    -e "s|__security__|$security|g" \
    -e "s|__sni__|$sni|g" \
    -e "s|__allowInsecure__|$allowInsecure|g" \
    -e "s|__path__|$path|g" \
    -e "s|__header_host__|$header_host|g" \
    -e "s|__browser_fp__|$browser_fp|g" \
    -e "s|__pub_key__|$pub_key|g" \
    -e "s|__short_id__|$short_id|g" \
    -e "s|__spiderX__|$spiderX|g" \
    -e "s|__alpn__|$alpn|g" \
  "$template" > "${cfg_file}"
  echo -e "${ansi_white}Конфигурационный файл настроен${ansi_std}"
}

url_config() {
  local link="$1"
  [ -z "$CONF" ] && echo -e "${ansi_red}❌ Не задан путь к конфигу \$CONF${ansi_std}" && return 1
	[ -z "$link" ] && read_value "${ansi_green}🔗 Введите ссылку Xray (ss:// или vless://)" link
	[ -z "$link" ] || [[ "$link" =~ ^[Qq]$ ]]  && return 1
  case "$link" in
    vless://*) parse_vless "$link" "$LOCAL_PORT" "$CONF" ;;
    trojan://*) parse_trojan "$link" "$LOCAL_PORT" "$CONF" ;;
    ss://*) parse_shadowsocks "$link" "$LOCAL_PORT" "$CONF" ;;
#    trojan://*) parse_trojan "$link" ;;
    *) echo -e "${ansi_red}Неподдерживаемый протокол${ansi_std}"; return 1 ;;
  esac
}

ping_start_bg() {
    local ping_host="$1"
    (
      ping -c "$PING_COUNT" -W "$PING_TIMEOUT" "$ping_host" 2>&1 
      echo -e "${ansi_yellow}⚠️  Пинг завершился, но тесты всё ещё выполняются (зависит от скорости соединения), пожалуйста, подождите...${ansi_std}"
    ) & 
    PING_PID=$!
}

start_speed_test() {
  local log_file="$1"
  local max_attempts=3
  local attempt=1

  while [ $attempt -le $max_attempts ]; do
    speed_test=$(curl -s --max-time 60 -w "%{http_code}|%{size_download}|%{time_namelookup}|%{time_connect}|%{time_starttransfer}|%{time_total}|%{speed_download}\n" \
        -x http://127.0.0.1:$TEST_PORT -o /dev/null "$URL_TEST")

    IFS='|' read -r http_code size_file t_namelookup t_connect t_starttransfer t_total speed_bytes <<EOF
$speed_test
EOF
    # Проверка на успех: код 200 и размер хотя бы 10 МБ (10485760 байт)
    if [ "$http_code" = "200" ] && [ "$size_file" -ge 10485760 ]; then
      return 0
    fi
    echo "Попытка $attempt из $max_attempts не удалась (код: $http_code, размер: $size_file байт, скорость $speed_bytes байт/с), повтор ..." >> "$log_file"
    attempt=$((attempt + 1))
    sleep 2
  done
  return 1
}

replace_inbounds() {
  local file_conf="$1"
  local file_log="$2"
  awk -v testport="$TEST_PORT" '
  /"inbounds"\s*:/ {
    print "\"inbounds\": ["
    print "  {\"port\": "testport", \"listen\": \"127.0.0.1\", \"protocol\": \"http\", \"settings\": {}}"
    skip=1
    next
  }
  skip {
    # Ищем закрытие массива
    if ($0 ~ /^\s*]\s*,?\s*$/) {
      print "],"
      skip=0
    }
    next
  }
  { print }
  ' "$file_conf" > "${file_conf}.mod" && mv "${file_conf}.mod" "$file_conf"
  
  sed -i "s|\"error\": \".*\"|\"error\": \"$file_log\"|" "$file_conf"
  sed -i "s|\"loglevel\": \".*\"|\"loglevel\": \"debug\"|" "$file_conf"
}

# Если пользователь прервет основной скрипт убить и дочерние если создавались
cleanup_test() {
  if [ -n "$XRAY_PID" ] && kill -0 "$XRAY_PID" 2>/dev/null; then
    kill "$XRAY_PID" 2>/dev/null
  fi  
}

test_url(){
  local link="$1"
  [ -z "$link" ] && read_value "${ansi_green}🔗 Введите ссылку Xray (ss:// или vless://)" link
  [ -z "$link" ] || [[ "$link" =~ ^[Qq]$ ]]  && return 1
  local temp_conf="/tmp/xray-test.json"
  local temp_log="/tmp/xray-test.log"
  local server_address
  trap cleanup_test EXIT INT TERM
  case "$link" in
    vless://*) 
        parse_vless "$link" "$TEST_PORT" "$temp_conf" 
        server_address=$(sed 's|//.*||; s|#.*||; /^$/d' "$temp_conf" | jq -r '.outbounds[0].settings.vnext[0].address')
        ;;
    ss://*) 
        parse_shadowsocks "$link" "$TEST_PORT" "$temp_conf" 
        server_address=$(sed 's|//.*||; s|#.*||; /^$/d' "$temp_conf" | jq -r '.outbounds[0].settings.servers[0].address')
        ;;
    trojan://*)
        parse_trojan "$link" "$TEST_PORT" "$temp_conf"
        server_address=$(sed 's|//.*||; s|#.*||; /^$/d' "$temp_conf" | jq -r '.outbounds[0].settings.servers[0].address')
        ;;
    *) echo -e "${ansi_red}Неподдерживаемый протокол${ansi_std}"; return 1 ;;
  esac
  [ ! -f "$temp_conf" ] && { echo -e "${ansi_red}❌ Нет сгенерированного конфигурационного файла: ${temp_conf}${ansi_std}"; return 1; }
  [ -z "$server_address" ] && { echo -e "${ansi_red}❌ Не удалось получить адрес сервера ${ansi_std}"; return 1; }
  # Заменяем inbounds на HTTP-прокси
  replace_inbounds "$temp_conf" "$temp_log"
  
    # Шаг 1: Измеряем пинг до запуска xray
  echo -e "${ansi_blue}Шаг 1: Проверка доступности сервера (${server_address})...${ansi_std}"
  ping -c "$PING_COUNT" -W "$PING_TIMEOUT" "$server_address"
  echo -e "${ansi_green}✅ Замер задержки окончен.${ansi_std}"  

  # Шаг 2: Запуск xray
  echo -e "${ansi_blue}Шаг 2: Запускаем $PR_NAME с тестовым конфигом...${ansi_std}"
  $PROC run -c "$temp_conf" >"$temp_log" 2>&1 &
  XRAY_PID=$!

  # Ждём запуска процесса (макс 10 секунд)
  i=0
  while [ "$i" -lt 10 ]; do
      if kill -0 "$XRAY_PID" 2>/dev/null; then
        echo -e "${ansi_green}✅ $PR_NAME test instance был запущен (PID: $XRAY_PID)${ansi_std}"
        break
      fi
    sleep 1
    i=$((i + 1))
  done
  # Проверка: успел ли стартовать
  if ! kill -0 "$XRAY_PID" 2>/dev/null; then
    echo -e "${ansi_red}❌ Не удалось запустить $PR_NAME test instance${ansi_std}"
    [ -f "$temp_log" ] && { echo "--- Содержимое лога ---"; cat "$temp_log"; }
    return 1
  fi
  # проверяем в лог файле что сервер запустился 
  i=0
  success=0
  while [ $i -lt 10 ]; do
      sleep 1
      # 1. Если порт открыт — это 100% успех, выходим из цикла
      if netstat -lnpt 2>/dev/null | grep -q ":$TEST_PORT"; then
        success=1
        break
      fi
      # 2. Если в логе ошибка старта (для sing-box ищем "FATAL" или "failed") — выходим сразу
      if grep -q "Failed to start" "$temp_log"; then
        success=0
        break
      fi
      i=$((i + 1))
  done

  if [ "$success" -eq 0 ]; then
      echo -e "${ansi_red}❌ Ошибка: не удалось дождаться открытия порта проверки: $TEST_PORT${ansi_std}"
      [ -f "$temp_log" ] && { echo "--- Лог ошибок бинарника ---"; cat "$temp_log"; }
      kill "$XRAY_PID" 2>/dev/null
      rm -f "$temp_conf" "$temp_log"
      return 1
  fi

  echo -e "${ansi_white}🔍 Проверка IP через прокси на myip.wtf ...${ansi_std}"
  local output

  output=$(curl -s --max-time 10 -x http://127.0.0.1:$TEST_PORT https://ipv4.myip.wtf/json)
  # проверяем что ответ получен
  if echo "$output" | grep -q '"YourFuckingIPAddress"'; then

    echo "$output" | awk '
        /"YourFuckingIPAddress"/   { sub(/^.*: /, ""); gsub(/[",]/,""); print "   🌐 IP         : " $0 }
        /"YourFuckingLocation"/    { sub(/^.*: /, ""); gsub(/[",]/,""); print "   📍 Location   : " $0 }
        /"YourFuckingHostname"/    { sub(/^.*: /, ""); gsub(/[",]/,""); print "   🖥 Hostname    : " $0 }
        /"YourFuckingISP"/         { sub(/^.*: /, ""); gsub(/[",]/,""); print "   🏢 ISP        : " $0 }
        /"YourFuckingCity"/        { sub(/^.*: /, ""); gsub(/[",]/,""); print "   🏙 City        : " $0 }
        /"YourFuckingCountry"/     { sub(/^.*: /, ""); gsub(/[",]/,""); print "   🌎 Country    : " $0 }
    '
    echo -e ""
    echo -e "${ansi_white}   🔍 Запускаем проверку скорости ...${ansi_std}"

    # --- ОКОНЧАТЕЛЬНЫЙ БЛОК ТЕСТА СКОРОСТИ (ЛИНЕЙНЫЙ) ---
    local attempt=1
    local max_attempts=3
    local success_download=0
    
    while [ $attempt -le $max_attempts ]; do
      echo -e "${ansi_white}      Попытка $attempt из $max_attempts...${ansi_std}"
      
      # Очищаем старый временный лог перед каждым замером
      : > /tmp/curl_time.txt
      
      # curl показывает живой прогресс-бар на экране, а тайминги пишет в файл
      curl --progress-bar --max-time 60 \
          -w "%{http_code}|%{size_download}|%{time_namelookup}|%{time_connect}|%{time_starttransfer}|%{time_total}|%{speed_download}\n" \
          -x http://127.0.0.1:$TEST_PORT \
          -o /dev/null "$URL_TEST" > /tmp/curl_time.txt

      # Считываем полученные тайминги в переменные текущей сессии
      IFS='|' read -r http_code size_file t_namelookup t_connect t_starttransfer t_total speed_bytes <<EOF
$(cat /tmp/curl_time.txt)
EOF
      rm -f /tmp/curl_time.txt
      
      # Проверка: код 200 и размер соответствует переменной URL_TEST_SIZE
      if [ "$http_code" = "200" ] && [ "$size_file" -ge "$URL_TEST_SIZE" ]; then
        success_download=1
        break
      fi
      
      echo -e "${ansi_yellow}      ⚠️ Попытка не удалась (код: $http_code, получено: $size_file байт), повтор...${ansi_std}"
      attempt=$((attempt + 1))
      sleep 2
    done
    # --- КОНЕЦ БЛОКА ТЕСТА СКОРОСТИ ---
    
    # Обработка результатов, если скачивание завершилось успехом
    if [ "$success_download" -eq 1 ]; then
      echo -e "${ansi_green}    ✅ Успешно выполнен тест скорости${ansi_std}"
      
      # Вычисления через awk (работают идеально, так как переменные не потерялись)
      latency_ms=$(awk "BEGIN { printf \"%.2f\", ($t_connect - $t_namelookup) * 1000 }")
      wait_ms=$(awk "BEGIN { printf \"%.2f\", ($t_starttransfer - $t_connect) * 1000 }")
      download_time_s=$(awk "BEGIN { printf \"%.2f\", $t_total - $t_starttransfer }")
      speed_mbps=$(awk "BEGIN { printf \"%.2f\", ($speed_bytes * 8) / 1000000 }")
      dns_ms=$(awk "BEGIN { printf \"%.2f\", $t_namelookup * 1000 }")   
      
      print_line
      echo " ⏱️  DNS Lookup:        $dns_ms мс"
      echo " ⏱️  Латентность TCP:   $latency_ms мс"
      echo " ⏱️  Ожидание ответа:   $wait_ms мс"
      echo " ⏱️  Скачивание файла:  $download_time_s сек"
      echo "     Скорость:          $speed_mbps Мбит/с"
      # echo " ⏱️  Время до установления TCP+TLS соединения:  ${connect_time}s"
      # echo " ⏱️  Время до ответа сервера                 :  ${starttransfer_time}s"
      # echo "            Если это время большое — значит сервер тормозит, загружен или далеко."
      # echo " ⏱️  Полное время загрузки (Total)           :  ${total_time}s"      
    else
      echo -e "${ansi_red}    ❌ Не удалось измерить скорость после $max_attempts попыток${ansi_std}"
    fi  
  else
    echo -e "${ansi_red}❌ Прокси не работает или сайт myip.wtf не отвечает${ansi_std}"
    print_line
    [ -f "$temp_log" ] && { echo "--- Содержимое лога ---"; cat "$temp_log"; }
  fi

  # Убить sing-box
  echo -e "${ansi_white}Проверка завершилась, производим остановку $PR_NAME${ansi_std}" 
  if kill "$XRAY_PID" 2>/dev/null; then
    i=0
    while [ "$i" -lt 5 ]; do
        if ! kill -0 "$XRAY_PID" 2>/dev/null; then
            break
        fi
        sleep 1
        i=$((i + 1))
    done
    if kill -0 "$XRAY_PID" 2>/dev/null; then
        echo -e "${ansi_yellow}⚠️ $PR_NAME не завершился, принудительное убийство${ansi_std}"
        kill -9 "$XRAY_PID" 2>/dev/null
    fi
  fi
  # Очистка
  rm -f "$temp_conf" "$temp_log" 
}

start(){
  local desc="$PR_NAME $ARGS"
	# Запуск демона/применение настроек
  [ "$INTERACTIVE" -eq 1 ] && echo -e -n "$ansi_white Запускаем процесс $desc ... $ansi_std"
  PID=$(get_pid)
  if [ -n "$PID" ]; then
    [ "$INTERACTIVE" -eq 1 ] && echo -e "            $ansi_yellow уже запущен. $ansi_std" || echo '{"status":"alive"}'
    return 0
  fi
  # shellcheck disable=SC2086 
  $PROC $ARGS > /dev/null 2>&1 &
  for i in $(seq 1 10); do
    sleep 1
    PID=$(get_pid)
    if [ -n "$PID" ]; then
      [ "$INTERACTIVE" -eq 1 ] && echo -e "            $ansi_green успешно. $ansi_std"
      logger "Успешно запущен процесс $desc. PID=$PID"
      return 0
    fi
  done
  [ "$INTERACTIVE" -eq 1 ] && echo -e "            $ansi_red не запущен. $ansi_std"
  logger "Не удалось запустить $desc"
  return 255
}

stop() {
  # Остановка демона/откат
  local desc="$PR_NAME $ARGS"
  PID=$(get_pid)

	case "$1" in
      stop | restart)
          [ "$INTERACTIVE" -eq 1 ] && echo -e -n "$ansi_white Останавливаем процесс $desc ... $ansi_std"
          [ -n "$PID" ] && kill "$PID"
        ;;
    	kill)
          [ "$INTERACTIVE" -eq 1 ] && echo -e -n "$ansi_white Уничтожаем процесс $desc ... $ansi_std"
          [ -n "$PID" ] && kill -9 "$PID"
        ;;
	esac	
  for i in $(seq 1 10); do
    sleep 1
    PID=$(get_pid)
    [ -z "$PID" ] && break
  done
  if [ -z "$PID" ]; then
    [ "$INTERACTIVE" -eq 1 ] && echo -e "            $ansi_green успешно. $ansi_std"
    logger "Процесс $desc успешно уничтожен."
    return 0
  fi
	[ "$INTERACTIVE" -eq 1 ] && echo -e "            $ansi_red ошибка. $ansi_std"	
    logger "Не удалось остовить процесс $desc"
    return 255
}

check() {
    local PID desc="$PR_NAME $ARGS"
    PID=$(get_pid)
    [ "$INTERACTIVE" -eq 1 ] && echo -e -n "$ansi_white Проверяем запущен ли процесс $desc ... $ansi_std"
    if [ -n "$PID" ]; then
        if [ "$INTERACTIVE" -eq 1 ]; then
            echo -e "            ${ansi_green}работает. $ansi_std"
        else
            echo '{"status":"alive"}'
        fi
        return 0
    else
        if [ "$INTERACTIVE" -eq 1 ]; then
            echo -e "            ${ansi_red}не найден. $ansi_std"
        else
            echo '{"status":"dead"}'
        fi
        return 1
    fi
}

print_help() {
  echo -e "${ansi_green}Использование:${ansi_std} ./xray-core.sh ${ansi_yellow}(start|restart|stop|check|status|info|get_param|set_url|test_url|help)${ansi_std}\n"

  echo -e "${ansi_blue}Команды плагина Xray для KVL:${ansi_std}"

  echo -e "  ${ansi_yellow}start${ansi_std}        — Запуск экземпляра Xray на основе текущей конфигурации."
  echo -e "  ${ansi_yellow}restart${ansi_std}      — Перезапуск плагина Xray (остановка + запуск)."
  echo -e "  ${ansi_yellow}stop${ansi_std}         — Остановка текущего экземпляра Xray."
  echo -e "  ${ansi_yellow}check|status${ansi_std} — Проверка состояния процесса Xray (PID, активность)."
  echo -e "  ${ansi_yellow}info${ansi_std}         — Возвращает описание плагина для интерфейса выбора:"
  echo -e "                      - читаемое имя плагина,"
  echo -e "                      - краткое описание,"
  echo -e "                      - метод маршрутизации (для KVL)."
  echo -e "  ${ansi_yellow}get_param${ansi_std}    — Возвращает параметры конфигурации плагина в формате JSON,"
  echo -e "                      используемые основной программой KVL для настройки iptables и маршрутизации."
  echo -e "  ${ansi_yellow}url set${ansi_std}      — Устанавливает новую ссылку подключения (ss:// или vless://),"
  echo -e "                      на её основе формируется конфигурация Xray."
  echo -e "  ${ansi_yellow}url test${ansi_std}     — Временная проверка подключения к серверу по указанной ссылке,"
  echo -e "                      без изменения текущих настроек. Выполняет запрос к https://myip.wtf/json"
  echo -e "                      и показывает внешний IP, город, страну, хост и провайдера."
  echo -e "  ${ansi_yellow}help${ansi_std}         — Выводит эту справку.\n"

  echo -e "${ansi_green}Пример использования:${ansi_std}"
  echo -e "  kvl plugin xray url set \"vless://...\""
  echo -e "  kvl plugin xray url test"
}

case "$1" in
  start)
	  start
    ;;
  stop|kill)
	  stop "$1"
    ;;
  restart)
    check > /dev/null && stop "$1"
    start
    ;;	
  check|status)
    check
    ;;	
  info)
    desc=$(sed 's|//.*||; s|#.*||; /^$/d' "$CONF" | jq -r '.desc // "нет тэга описания"')
    if [ "$INTERACTIVE" -eq 1 ]; then
      echo "Плагин: $PR_NAME Версия: $VERSION"
		  echo "Тип: $PR_TYPE"
		  echo "Описание: $desc"
    else
        echo "{\"name\":\"$PR_NAME\",\"description\":\"$desc\",\"type\":\"$PR_TYPE\",\"method\":\"$METOD\"}"
    fi
    ;;
  get_param)
    IFS='|'
    read -r local_port network server <<EOF
$(sed 's|//.*||; s|#.*||; /^$/d' "$CONF" | jq -r '
    .inbounds[0].port as $port |
    .inbounds[0].settings.network as $network |
    .outbounds[0].settings.vnext[0].address as $address |
    "\($port)|\($network)|\($address)"
    ')
EOF
    unset IFS
    # Проверка поддержки UDP
    if echo "$network" | grep -q 'udp'; then
      udp="yes"
    else
      udp="no"
    fi
    ip=$(resolve_ip "$server")
    echo "{\"inface_cli\":\"$PR_NAME\",\"method\":\"$METOD\",\"udp\":\"$udp\",\"tcp_way\":\"$TCP_WAY\",\"tcp_port\":\"$local_port\",\"udp_port\":\"$local_port\",\"server_ip\":\"$ip\"}"
    ;;
  url)
    case "$2" in
      set)
        # строки вида ss:// — плагин сам разбирает и сохраняет
	      url_config "$3"
        ;;
      test)
        test_url "$3"
        ;;  
      *)
        echo "Usage: $0 url (set|test)" >&2; exit 1
        ;;  
    esac
    ;;
  help)  
    print_help
    ;;
  *)
    echo "Usage: $0 (start|restart|stop|check|status|info|get_param|url|help)" >&2; exit 1
    ;;
esac
