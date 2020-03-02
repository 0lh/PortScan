import click
import subprocess
import re
import nmap
import threading
import os
from queue import Queue

lock = threading.Lock()
rate = 1200

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
        command = f'sudo masscan {ip} --top-ports 100 --rate={rate} --wait 5'
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
                    if len(ip_port_dict.get(ip)) < 30:
                        click.secho(f'{ip} => 当前端口个数{len(ip_port_dict.get(ip))}', fg='red')
                        ip_port_dict[ip].append(open_port[0])

                    else:
                        click.secho(f'\n{ip} \n疑似有WAF,存活端口大于个', fg='red')
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
            ret = np.scan(ip, f'{open_ports}', arguments="-sV -sT -Pn --version-all --open")
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


import csv


def gen_one_csv(csv_filename, port_list):
    test_list = []
    for site_status_info in port_list:
        test_list.append(site_status_info)

    headers = ['url', 'status code', 'title']
    with open('{}.csv'.format(csv_filename), 'w', newline='', encoding='utf-8')as f:
        f_csv = csv.writer(f)
        f_csv.writerow(headers)
        f_csv.writerows(test_list)


def save_result_to_csv():
    result_list = []

    #         result_list.append(f'{ip}:{port}')
    # print('result_list: ', result_list)

    header = ['ip_port']
    with open('ip_port.csv', 'w', newline='', encoding='utf-8')as f:
        f_csv = csv.writer(f)
        # f_csv.writerow(header)
        for ip, port_list in ip_port_dict.items():
            for port in port_list:
                f_csv.writerow([f'{ip}:{port}'])
    # todo 排序写入 or 排序写出


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

    # save_result_to_csv()


if __name__ == '__main__':
    main()
    print('ip_port_dict => ', ip_port_dict)
