import os
import dpkt
import socket

pcaps = os.listdir('pcaps/')
protocols = {num:name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}
SINGLE = 16384
# TCP   30 32 60 64 128         255
# UDP   30 32 60 64 128
# ICMP     32    64 128 200 254 255

with open('result.csv', 'w') as r:
    r.write('name,')
    r.write('len,')
    r.write('ttl(32),')
    r.write('ttl(64),')
    r.write('ttl(128),')
    r.write('ttl(255),')
    r.write('id(new),')
    r.write('id(overlap),')
    r.write('off(single),')
    r.write('off(frag),')
    r.write('sum(new),')
    r.write('sum(overlap)')

    for p in protocols.values():
        r.write(',' + str(p))

    r.write('\n')

    for pcap in pcaps:
        lookingFile = os.getcwd() + '/pcaps/' + pcap

        with open(lookingFile, 'rb') as f: 
            result = {}
            result['name'] = ''
            result['len'] = 0
            result['ttl(32)'] = 0
            result['ttl(64)'] = 0
            result['ttl(128)'] = 0
            result['ttl(255)'] = 0
            result['id(new)'] = 0
            result['id(overlap)'] = 0
            result['off(single)'] = 0
            result['off(frag)'] = 0
            result['sum(new)'] = 0
            result['sum(overlap)'] = 0
            for p in protocols.values():
                result[p] = 0

            TTLs = []
            IDs = []
            checksums = []
            count = 0
            print(pcap)
            reader = dpkt.pcap.Reader(f)

            for timestamp, buf in reader:
                count += 1
                eth = dpkt.ethernet.Ethernet(buf)
                # print(eth.__dict__)
                ip = eth.data

                try:
                    result['len'] += int(ip['len'])

                    target = int(ip['ttl'])
                    if target <= 32:
                        result['ttl(32)'] += 1
                    elif target <= 64:
                        result['ttl(64)'] += 1
                    elif target <= 128:
                        result['ttl(128)'] += 1
                    elif target <= 255:
                        result['ttl(255)'] += 1

                    result[protocols[int(ip['p'])]] += 1
                    
                    target = int(ip['id'])
                    if target not in IDs:
                        IDs.append(target)
                        result['id(new)'] += 1
                    else:
                        result['id(overlap)'] += 1

                    target = int(ip['off'])
                    if target == SINGLE:
                        result['off(single)'] += 1
                    else:
                        result['off(frag)'] += 1

                    target = int(ip['sum'])
                    if target not in checksums:
                        checksums.append(target)
                        result['sum(new)'] += 1
                    else:
                        result['sum(overlap)'] += 1
                    
                except:
                    continue

            result['len'] /= count
            
            for p in protocols.values():
                result[p] /= count

            result['id(new)'] /= count
            result['id(overlap)'] /= count
            result['off(single)'] /= count
            result['off(frag)'] /= count
            result['sum(new)'] /= count
            result['sum(overlap)'] /= count
            result['ttl(32)'] /= count
            result['ttl(64)'] /= count
            result['ttl(128)'] /= count
            result['ttl(255)'] /= count

            r.write(str(pcap[11:-5]) + ',')
            r.write(str(result['len']) + ',')
            r.write(str(result['ttl(32)']) + ',')
            r.write(str(result['ttl(64)']) + ',')
            r.write(str(result['ttl(128)']) + ',')
            r.write(str(result['ttl(255)']) + ',')
            r.write(str(result['id(new)']) + ',')
            r.write(str(result['id(overlap)']) + ',')
            r.write(str(result['off(single)']) + ',')
            r.write(str(result['off(frag)']) + ',')
            r.write(str(result['sum(new)']) + ',')
            r.write(str(result['sum(overlap)']))

            for p in protocols.values():
                if p in result:
                    r.write(',' + str(result[p]))
                else:
                    r.write(',0')
            
            r.write('\n')