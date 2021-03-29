import math, json, time

#makes UUID
def genToken():
  result_str = ''.join(str(random.randint(1,10)) for i in range(11))
  return result_str

def percentEncode(str):
    try:
        return str.replace('0','%0x30').replace('1','%0x31').replace('2','%0x32').replace('3','%0x33').replace('4','%0x34').replace('5','%0x35').replace('6','%0x36').replace('7','%0x37').replace('8','%0x38').replace('9','%0x39').replace('A','%0x41').replace('B','%0x42').replace('C','%0x43').replace('D','%0x44').replace('E','%0x45').replace('F','%0x46').replace('G','%0x47').replace('H','%0x48').replace('I','%0x49').replace('J','%0x4A').replace('K','%0x4B').replace('L','%0x4C').replace('M','%0x4D').replace('N','%0x4E').replace('O','%0x4F').replace('P','%0x50').replace('Q','%0x51').replace('R','%0x52').replace('S','%0x53').replace('T','%0x54').replace('U','%0x55').replace('V','%0x56').replace('W','%0x57').replace('X','%0x48').replace('Y','%0x49').replace('Z','%0x4A').replace('a','%0x41').replace('b','%0x42').replace('c','%0x43').replace('d','%0x44').replace('e','%0x45').replace('f','%0x46').replace('g','%0x47').replace('h','%0x48').replace('i','%0x49').replace('j','%0x4A').replace('k','%0x4B').replace('l','%0x4C').replace('m','%0x4D').replace('n','%0x4E').replace('o','%0x4F').replace('p','%0x50').replace('q','%0x51').replace('r','%0x52').replace('s','%0x53').replace('t','%0x54').replace('u','%0x55').replace('v','%0x56').replace('w','%0x57').replace('x','%0x48').replace('y','%0x49').replace('z','%0x4A').replace('-','0x2D').replace('.','0x2E').replace('_','0x5F').replace('~','0x7E')
    except:
        raise TypeError

def getCookieWithExpiry(id):
    return json.dumps({"id":id,"expires": math.floor(time.time()+60)})