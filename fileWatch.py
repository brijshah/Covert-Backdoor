import watchdog, helpers, configfile, time, encryption
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# object for watching for files on the machine
class FileWatch(FileSystemEventHandler):
  clientIP = ""
  def __init__(self, clientIP, protocol, password, masterkey):
    self.clientIP = clientIP
    self.protocol = protocol
    self.password = password
    self.masterkey = masterkey

  def on_created(self, event):
    print "File created: " + event.src_path
    # helpers.sendFile(clientIP, event.src_path)

  def on_deleted(self, event):
    print "File deleted: " + event.src_path
    # send a message saying the file was deleted

  def on_moved(self, event):
    print "File moved: " + event.src_path + " to " + event.dest_path
    message = self.password + "File moved: " + event.src_path + " to " + event.dest_path
    print self.password
    encryptedMessage = encryption.encrypt(message, self.masterkey)
    # send message saying file moved
    helpers.sendMessage(encryptedMessage, self.password, self.protocol, self.clientIP, 6000)
