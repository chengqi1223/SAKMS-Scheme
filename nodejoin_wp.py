import os
import sys
import time
from ctypes import *
MD5 = cdll.LoadLibrary('./MD5.dll')
montogomery_pro = cdll.LoadLibrary('./windows_projective.dll')

arry = c_uint8*20
arry_2 = c_uint8*40
arry_3 = c_uint8*8

my_serect = arry()
my_public = arry_2()
node_Ra = arry_2()
node_id = arry_3()
node_rca = arry()
node_Rca = arry_2()
node_cert = arry()
node_w = arry()


#select private key  { 0xbf,0x20,0x35,0xbd,0x30,0xa7,0xe6,0x3a,0xbd,0xc6,0xb3,0xab,0x8,0x5c,0xe6,0x33,0xc2,0x24,0x5,0x7a }
my_serect[0] = c_uint8(0xbf)
my_serect[1] = c_uint8(0x20)
my_serect[2] = c_uint8(0x35)
my_serect[3] = c_uint8(0xbd)
my_serect[4] = c_uint8(0x30)
my_serect[5] = c_uint8(0xa7)
my_serect[6] = c_uint8(0xe6)
my_serect[7] = c_uint8(0x3a)
my_serect[8] = c_uint8(0xbd)
my_serect[9] = c_uint8(0xc6)
my_serect[10] = c_uint8(0xb3)
my_serect[11] = c_uint8(0xab)
my_serect[12] = c_uint8(0x8)
my_serect[13] = c_uint8(0x5c)
my_serect[14] = c_uint8(0xe6)
my_serect[15] = c_uint8(0x33)
my_serect[16] = c_uint8(0xc2)
my_serect[17] = c_uint8(0x24)
my_serect[18] = c_uint8(0x5)
my_serect[19] = c_uint8(0x7a)

montogomery_pro.uECC_compute_public_key_wp(my_serect ,my_public )

here = sys.path[0]
print here
sys.path.insert(0,os.path.join(here,'..','..','..','coap'))

from coap import coap
import signal

MOTE_IP = 'bbbb::1415:9205:101:1e'

c = coap.coap()

# read the information about the board status
start_time = time.time()
p = c.GET('coap://[{0}]/nj'.format(MOTE_IP))


for i in range(8):
    node_id[i] = c_uint8(p[i])

for i in range(40):
    node_Ra[i] = c_uint8(p[i+8])


# select rca
for i in range(20):
    node_rca[i] = c_uint8(24)
#compte Pa
#3.rca*G
montogomery_pro.uECC_compute_public_key_wp(node_rca, node_Rca )




#4.Pa
x1 = arry()
y1 = arry()
x2 = arry()
y2 = arry()
for i in range(20):
    x1[i] = node_Rca[i]
    y1[i] = node_Rca[i+20]
    x2[i] = node_Ra[i]
    y2[i] = node_Ra[i+20]

montogomery_pro.uECC_point_add_wp(x1, y1, x2, y2)

# cert
for i in range(20):
    node_cert[i] = c_uint8(0x11)

#compute w

#11.
# hash operation

class MD5Context(Structure):
     _fields_ = [('size',c_uint64),
                 ('buffer',c_uint32*4),
                 ('input',c_uint8*64),
                 ('digest',c_uint8*16)]
ctx = MD5Context()
MD5.md5Init(byref(ctx))
MD5.md5Update(byref(ctx),node_cert,c_uint64(20))
MD5.md5Finalize(byref(ctx))
end_time = time.time()



#5
temp = arry()
temp_1 = arry()
for i in range(4):
    temp[i] = c_uint8(0)

for i in range(16):
    temp[i+4] = ctx.digest[i]

montogomery_pro.uECC_n_operation_wp(node_w, temp, node_rca, my_serect)
end_time = time.time()



payload_1 = [1]
#Pa(40B)
for i in range(20):
    payload_1.append(int(x1[i]))

for i in range(20):
    payload_1.append(int(y1[i]))

end_time = time.time()

p = c.PUT(
    'coap://[{0}]/nj'.format(MOTE_IP),
    payload = payload_1,
)


payload_2 = [2]
#w(20B)
for i in range(20):
    payload_2.append(int(node_w[i]))
#certa(20B)
for i in range(20):
    payload_2.append(int(node_cert[i]))

p = c.PUT(
    'coap://[{0}]/nj'.format(MOTE_IP),
    payload = payload_2,
)
end_time = time.time()
print("time cost:", float(end_time - start_time) * 1000.0, "ms")



while True:
        input = raw_input("Done. Press q to close. ")
        if input=='q':
            print 'bye bye.'
            #c.close()
            os.kill(os.getpid(), signal.SIGTERM)
