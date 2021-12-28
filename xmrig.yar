rule xmrig
{
  meta:
    description = "https://xmrig.com/"
    author = "ivoripuion"
    date = "2021/12/28"
  
  strings:
    $s1 = "Usage: xmrig "
  
  condition:
    $s1 and uint32(0) == 0x464C457F
}
