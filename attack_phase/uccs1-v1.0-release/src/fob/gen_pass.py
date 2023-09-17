import secrets
import string

def create_secret(pwd_length):
  letters = string.ascii_letters
  digits = string.digits
  #special_chars = string.punctuation
  alphabet = letters + digits #+ special_chars
  
  pwd_length = pwd_length
  SECRET = ''
  
  for i in range(pwd_length):
    ch = secrets.choice(alphabet)
    while ch == "\"" or ch == "\\" or ch == "'":
      ch = secrets.choice(alphabet)
    
    SECRET += ''.join(ch)
  
  return SECRET


def main():
    psim = create_secret(16)
    hsim = create_secret(15)
    tsim = create_secret(16)
    fob_sec = create_secret(16)
    passwd = create_secret(11)
    
    
    with open("/secrets/global_secrets.txt","w") as f:
      f.write(fob_sec+','+psim+','+hsim+','+tsim+','+passwd)
  
  
if __name__ == "__main__":
    main()
