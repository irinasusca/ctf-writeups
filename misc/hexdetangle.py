#split into 8 byte chunks and hex decode.
string = input("Enter tangled string:")
num = input("Enter chunks size (4 or 8 probably):")
num = int(num, 10)

i=0

while(i <= len(string)):
   chunk=string[i:i+num][::-1]
   #chunk = int(chunk, 16)
   print(chunk, end='')
   i=i+num
   
