# PcapInterceptor

## Как запустить?

0. Выполнить цель maven `mvn install`
0. Запустить сформированный jar-архив из директории target командой `java -jar interceptor {параметры}`

## Параметры

`hostname [filter]`

Параметр фильтра необязательный. О фильтрах гуглите pcap-filter.

Примеры:
- `192.168.0.26 "udp proto"`
- `192.168.0.21 "portrange 6000-6008"`
- `192.168.0.5`