import nmap

nm = nmap.PortScanner()
target = input('Введите ip адрес:')

nm.scan(hosts=target, arguments='-sP')

for host in nm.all_hosts():
     print('--------------------------------------------------')
     print('Хост: %s (%s)' % (host, nm[host].hostname()))
     print('Состояние хоста: %s' % nm[host].state())

     if nm[host].state() == 'up':
         for proto in nm[host].all_protocols():
             print('--------------------------------------------------')
             print('Протокол ; %s' % proto)
             lport = nm[host][proto].keys()
             for port in lport:
                 print('Порт : %stСостояние: %s' % (port, nm[host][proto][port]['state']))

print('Сканирование завершено.')
