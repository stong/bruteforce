import socket
from subprocess import Popen, PIPE
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 16969))
s.listen(1)

while True:
  conn, addr = s.accept()
  print 'Connection address:', addr
  data = conn.recv(1024)
  prefix = data.split('\n')[0]
  print 'prefix: %s' % (prefix,)
  Popen(['./fastpow', prefix], stdout=PIPE).communicate()
  output = open('sice.txt', 'r').read()
  print 'PoW: %s' % (output,)
  conn.send(output)
  conn.close()
  try:
    os.remove('sice.txt')
  except OSError:
    continue

