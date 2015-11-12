import os
import urllib

urllib.urlretrieve(" https://www.python.org/ftp/python/2.7.10/Python-2.7.10.tar.xz", filename="Python-2.7.10.tar.xz")
os.system("tar xvfJ Python-2.7.10.tar.xz")
os.system("dnf groupinstall \"Development tools\" -y")
os.system("dnf install zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel readline-devel tk-devel gdbm-devel db4-devel libpcap-devel xz-devel -y")
os.chdir("/root/Downloads/Python-2.7.10")
os.system("./configure")
os.system("make")
os.system("make install")
os.chdir("/root/Downloads")
urllib.urlretrieve("https://bootstrap.pypa.io/get-pip.py", filename="get-pip.py")
os.system("python get-pip.py")
os.system("pip install TripleSec")
