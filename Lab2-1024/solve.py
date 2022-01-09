import re
from pwn import *
from Crypto.Util.number import *

C = ['9F0B13944841A832B2421B9EAF6D9836',
     '813EC9D944A5C8347A7CA69AA34D8DC0',
     'DF70E343C4000A2AE35874CE75E64C31']
BLOCK = 2
div = len(C) / (BLOCK + 1)

r = remote('128.8.130.16', 49101)

def send_payload(cipher, number):
    msg = cipher[:]
    msg.insert(0, number)
    msg.append(0)

    r.send(bytes(msg))
    bit_recv = r.recv(numb=2)
    return int(bit_recv.decode()[0])

M = []
IVALUE = []
for b in range(BLOCK):
    print('[*] Detecting Block',b+1)
    IV = C[b]
    iv = '00000000000000000000000000000000'
    Ivalue = []
    iv = re.findall('.{2}', iv)[::-1]
    padding = 1

    for l in range(16):
        print("  [+] Detecting IVALUE's last", l + 1 , 'block')
        for ll in range(l):
            iv[ll] = hex(int(Ivalue[ll], 16) ^ padding)[2:].zfill(2)

        for n in range(256):
            iv[l] = hex(n)[2:].zfill(2)
            data = ''.join(iv[::-1]) + C[b + 1]
            
            ctext = [(int(data[i:i + 2], 16)) for i in range(0, len(data), 2)]
            rc = send_payload(ctext, 2)
            
            if str(rc) == '1':
                Ivalue += [hex(n ^ padding)[2:].zfill(2)]
                print('    [+] TEMP IVALUE =', ''.join(Ivalue[::-1]))
                break
        padding += 1

    Ivalue = ''.join(Ivalue[::-1])
    IVALUE += [Ivalue]

    print('  [+] IVALUE:', IVALUE)
    print('  [+] IV:', IV)
    m = re.findall('[0-9a-f]+', str(hex(int(IV, 16) ^ int(''.join(Ivalue), 16))))[1]
    M += [m]

    print('[#] Detecting Block', b + 1 ,'-- Done!')
    print('[#]', 'The IValue' + str(b + 1), 'is:', Ivalue)
    print('[#]', 'The M' + str(b + 1) , 'is:', m)
    print('-' * 50)

print('[!] The Intermediary Value is:', ''.join(IVALUE))
print('[!] The M is:', ''.join(M))
# 5961792120596f752067657420616e20412e203d290b0b0b0b0b0b0b0b0b0b0b

print('[^_^] The Flag is:', long_to_bytes(int(M, 16)))
# b'Yay! You get an A. =)'

'''log.txt
reverier at Reverier-Arch in ~/D/作/现/w/PA2-AES
[Crypto][!]: proxychains python solve.py
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/libproxychains4.so
[proxychains] DLL init: proxychains-ng 4.15
[◐] Opening connection to 128.8.130.16 on port 49101: Trying 128.8.130.16
[+] Opening connection to 128.8.130.16 on port 49101: Done
[*] Detecting Block 1
  [+] Detecting IVALUE's last 1 block
    [+] TEMP IVALUE = 16
  [+] Detecting IVALUE's last 2 block
    [+] TEMP IVALUE = f616
  [+] Detecting IVALUE's last 3 block
    [+] TEMP IVALUE = 0cf616
  [+] Detecting IVALUE's last 4 block
    [+] TEMP IVALUE = 8f0cf616
  [+] Detecting IVALUE's last 5 block
    [+] TEMP IVALUE = ea8f0cf616
  [+] Detecting IVALUE's last 6 block
    [+] TEMP IVALUE = 7eea8f0cf616
  [+] Detecting IVALUE's last 7 block
    [+] TEMP IVALUE = 257eea8f0cf616
  [+] Detecting IVALUE's last 8 block
    [+] TEMP IVALUE = 92257eea8f0cf616
  [+] Detecting IVALUE's last 9 block
    [+] TEMP IVALUE = 4792257eea8f0cf616
  [+] Detecting IVALUE's last 10 block
    [+] TEMP IVALUE = c74792257eea8f0cf616
  [+] Detecting IVALUE's last 11 block
    [+] TEMP IVALUE = 18c74792257eea8f0cf616
  [+] Detecting IVALUE's last 12 block
    [+] TEMP IVALUE = 6818c74792257eea8f0cf616
  [+] Detecting IVALUE's last 13 block
    [+] TEMP IVALUE = b56818c74792257eea8f0cf616
  [+] Detecting IVALUE's last 14 block
    [+] TEMP IVALUE = 6ab56818c74792257eea8f0cf616
  [+] Detecting IVALUE's last 15 block
    [+] TEMP IVALUE = 6a6ab56818c74792257eea8f0cf616
  [+] Detecting IVALUE's last 16 block
    [+] TEMP IVALUE = c66a6ab56818c74792257eea8f0cf616
  [+] IVALUE: ['c66a6ab56818c74792257eea8f0cf616']
  [+] IV: 9F0B13944841A832B2421B9EAF6D9836
[#] Detecting Block 1 -- Done!
[#] The IValue1 is: c66a6ab56818c74792257eea8f0cf616
[#] The M1 is: 5961792120596f752067657420616e20
--------------------------------------------------
[*] Detecting Block 2
  [+] Detecting IVALUE's last 1 block
    [+] TEMP IVALUE = cb
  [+] Detecting IVALUE's last 2 block
    [+] TEMP IVALUE = 86cb
  [+] Detecting IVALUE's last 3 block
    [+] TEMP IVALUE = 4686cb
  [+] Detecting IVALUE's last 4 block
    [+] TEMP IVALUE = a84686cb
  [+] Detecting IVALUE's last 5 block
    [+] TEMP IVALUE = 91a84686cb
  [+] Detecting IVALUE's last 6 block
    [+] TEMP IVALUE = ad91a84686cb
  [+] Detecting IVALUE's last 7 block
    [+] TEMP IVALUE = 77ad91a84686cb
  [+] Detecting IVALUE's last 8 block
    [+] TEMP IVALUE = 7177ad91a84686cb
  [+] Detecting IVALUE's last 9 block
    [+] TEMP IVALUE = 3f7177ad91a84686cb
  [+] Detecting IVALUE's last 10 block
    [+] TEMP IVALUE = c33f7177ad91a84686cb
  [+] Detecting IVALUE's last 11 block
    [+] TEMP IVALUE = aec33f7177ad91a84686cb
  [+] Detecting IVALUE's last 12 block
    [+] TEMP IVALUE = 6daec33f7177ad91a84686cb
  [+] Detecting IVALUE's last 13 block
    [+] TEMP IVALUE = e46daec33f7177ad91a84686cb
  [+] Detecting IVALUE's last 14 block
    [+] TEMP IVALUE = e9e46daec33f7177ad91a84686cb
  [+] Detecting IVALUE's last 15 block
    [+] TEMP IVALUE = 10e9e46daec33f7177ad91a84686cb
  [+] Detecting IVALUE's last 16 block
    [+] TEMP IVALUE = c010e9e46daec33f7177ad91a84686cb
  [+] IVALUE: ['c66a6ab56818c74792257eea8f0cf616', 'c010e9e46daec33f7177ad91a84686cb']
  [+] IV: 813EC9D944A5C8347A7CA69AA34D8DC0
[#] Detecting Block 2 -- Done!
[#] The IValue2 is: c010e9e46daec33f7177ad91a84686cb
[#] The M2 is: 412e203d290b0b0b0b0b0b0b0b0b0b0b
--------------------------------------------------
[!] The Intermediary Value is: c66a6ab56818c74792257eea8f0cf616c010e9e46daec33f7177ad91a84686cb
[!] The M is: 5961792120596f752067657420616e20412e203d290b0b0b0b0b0b0b0b0b0b0b
[*] Closed connection to 128.8.130.16 port 49101
'''
