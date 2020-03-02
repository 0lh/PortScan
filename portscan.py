import click
import subprocess
import re
import nmap
import threading
import os
from queue import Queue
from config import *
import csv

lock = threading.Lock()

ip_port_dict = {}

q = Queue()


class PortScan(threading.Thread):
    def __init__(self, q):
        super(PortScan, self).__init__()
        self.q = q

    def run(self):
        while not self.q.empty():
            ip = self.q.get()
            open_port_list = self.masscan_scan(ip)
            self.nmap_scan(ip, open_port_list)

    def masscan_scan(self, ip):
        command = f'sudo masscan {ip} -p{masscan_port} --rate={masscan_rate} --wait 5'
        lock.acquire()
        click.secho('\n' + '=>' * 50, fg='red')
        click.secho(f'[*] 当前command: {command}', fg='red')
        click.secho(f'开始masscan扫描目标 {ip}\n', fg='red')
        lock.release()
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        while not child.poll():
            output = child.stdout.readline()
            line = str(output, encoding='utf-8').strip()
            lock.acquire()
            print(line)
            lock.release()
            if 'Discovered open port' in line:
                open_port = re.findall(r'port (\d{1,5})/tcp', line)
                if ip_port_dict.get(ip):
                    if len(ip_port_dict.get(ip)) < 50:
                        click.secho(f'{ip} => 当前端口个数{len(ip_port_dict.get(ip))}', fg='red')
                        ip_port_dict[ip].append(open_port[0])
                    else:
                        click.secho(f'\n{ip} \n疑似有WAF,存活端口大于50个', fg='red')
                        del ip_port_dict[ip]
                        os.kill(child.pid, 9)
                else:
                    ip_port_dict[ip] = [open_port[0]]
            if subprocess.Popen.poll(child) == 0:
                break
        child.wait()
        if ip_port_dict.get(ip):
            return ip_port_dict[ip]
        else:
            return None

    def nmap_scan(self, ip, open_ports_list):
        if open_ports_list:
            with open('ip_port.csv', 'a', newline='', encoding='utf-8')as f:
                f_csv = csv.writer(f)
                # f_csv.writerow(header)
                for port in open_ports_list:
                    f_csv.writerow([f'{ip}:{port}'])
            np = nmap.PortScanner()
            open_ports = ",".join(open_ports_list)
            lock.acquire()
            click.secho(f'[*] 开始nmap扫描 ip: {ip} => 端口: {open_ports}', fg='red')
            lock.release()
            ret = np.scan(ip, f'{open_ports}', arguments=nmap_arguments)
            try:
                output_item = ret['scan'][ip]['tcp']
            except Exception:
                pass
            else:
                for port, port_info in output_item.items():
                    save_item = f"[+] {ip} {port} {port_info['name']} {port_info['product']} {port_info['version']}"
                    lock.acquire()
                    print(save_item)
                    lock.release()
                    with open('ports_info.txt', 'a+', encoding='utf-8') as f:
                        f.write(save_item + '\n')


def main():
    with open('ips.txt', 'r', encoding='utf-8') as f:
        for ip in f:
            q.put(ip.rstrip('\n'))
    tasks = []
    for _ in range(100):
        task = PortScan(q)
        task.start()
        tasks.append(task)

    for task in tasks:
        task.join()
    print('ip_port_dict => ', ip_port_dict)


if __name__ == '__main__':
    main()
