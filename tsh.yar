rule tsh
{
  meta:
    description = "https://github.com/orangetw/tsh"
    author = "ivoripuion"
    date = "2022/4/25"
  
  strings:
    $s1 = {58 90 AE 86 F1 B9 1C F6 29 83 95 71 1D DE 58 0D}
  condition:
    $s1
}


