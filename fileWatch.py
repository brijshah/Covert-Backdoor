import watchdog, helpers, configfile, time
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
  def __init__(self, clientIP):
    self.clientIP = clientIP

  def on_created(self, event):
    print "File created: " + event.src_path
    # helpers.sendFile(clientIP, event.src_path)

  def on_modified(self, event):
    print "File modified: " + event.src_path
    # helpers.sendFile(clientIP, event.src_path)

  def on_deleted(self, event):
    print "File deleted: " + event.src_path
    # send a message saying the file was delted

  def on_moved(self, event):
    print "File moved: " + event.src_path + " to " + event.dest_path
    # send message saying file moved

def main():
  observer = Observer()
  observer.schedule(FileWatch(), '/Users/callumstyan/git')
  observer.start()

  try:
    while True:
      time.sleep(1)
  except KeyboardInterrupt:
    observer.stop()

  observer.join()

main()