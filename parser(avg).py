import os
import dpkt
import socket

pcaps = os.listdir('pcaps/')
protocols = {num:name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}

with open('result.csv', 'w') as r:
    r.write('len,')
    r.write('ttl,')
    r.write('id(new),')
    r.write('id(overlap),')
    r.write('off(new),')
    r.write('off(overlap),')
    r.write('sum(new),')
    r.write('sum(overlap)')

    for p in protocols.values():
        r.write(',' + str(p))

    r.write('\n')

    for pcap in pcaps:
        lookingFile = os.getcwd() + '/pcaps/' + pcap

        with open(lookingFile, 'rb') as f: 
            result = {}
            result['len'] = 0
            result['ttl'] = 0
            result['id(new)'] = 0
            result['id(overlap)'] = 0
            result['off(new)'] = 0
            result['off(overlap)'] = 0
            result['sum(new)'] = 0
            result['sum(overlap)'] = 0
            for p in protocols.values():
                result[p] = 0

            IDs = []
            offsets = []
            checksums = []
            numLen = 0
            numTTL = 0
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
                    numLen += 1

                    result['ttl'] += int(ip['ttl'])
                    numTTL += 1

                    result[protocols[int(ip['p'])]] += 1
                    
                    target = int(ip['id'])
                    if target not in IDs:
                        IDs.append(target)
                        result['id(new)'] += 1
                    else:
                        result['id(overlap)'] += 1

                    target = int(ip['off'])
                    if target not in offsets:
                        offsets.append(target)
                        result['off(new)'] += 1
                    else:
                        result['off(overlap)'] += 1

                    target = int(ip['sum'])
                    if target not in checksums:
                        checksums.append(target)
                        result['sum(new)'] += 1
                    else:
                        result['sum(overlap)'] += 1
                    
                except:
                    continue

            result['len'] /= numLen
            result['ttl'] /= numTTL
            
            for p in protocols.values():
                result[p] /= count

            result['id(new)'] /= count
            result['id(overlap)'] /= count
            result['off(new)'] /= count
            result['off(overlap)'] /= count
            result['sum(new)'] /= count
            result['sum(overlap)'] /= count

            r.write(str(result['len']) + ',')
            r.write(str(result['ttl']) + ',')
            r.write(str(result['id(new)']) + ',')
            r.write(str(result['id(overlap)']) + ',')
            r.write(str(result['off(new)']) + ',')
            r.write(str(result['off(overlap)']) + ',')
            r.write(str(result['sum(new)']) + ',')
            r.write(str(result['sum(overlap)']))

            for p in protocols.values():
                if p in result:
                    r.write(',' + str(result[p]))
                else:
                    r.write(',0')
            
            r.write('\n')