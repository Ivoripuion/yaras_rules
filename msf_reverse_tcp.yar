rule x64_meterpreter_reverse_tcp 
{
  meta:
    description = "x64/meterpreter/reverse_tcp"
    author = "ivoripuion"
    date = "2021/11/25"

  strings:
    $s1 = {48 B9 ?? ?? ?? ?? ?? ?? ?? ?? 51 48 89 E6 6A 10 5A 6A 2A 58 0F 05 59 48 85 C0 79 25}
  
  condition:
    all of them and uint32(0) == 0x464C457F

}
