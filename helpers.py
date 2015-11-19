# take string and break it into chunks of length size
def chunkString(size, string):
  string = [string[i:i+size] for i in range(0, len(string), size)]
  return string
