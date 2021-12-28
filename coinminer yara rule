rule Rule_Coinminer_ELF_Format {
   meta:
      description = "Detects Crypto Miner ELF format"
      author = "Huseyin Rencber"
      reference = "Internal Researh & https://isc.sans.edu/diary/Example+of+how+attackers+are+trying+to+push+crypto+miners+via+Log4Shell/28172"
      date = "2021-12-27"
   strings:
      $str1 = "mining.set_difficulty" ascii
      $str2 = "mining.notify"  ascii
      $str3 = "GhostRider" ascii
      $str4 = "cn/turtle-lite" ascii
      $str5 = "spend-secret-key" ascii
   condition:
      uint16(0) == 0x457f and 
      4 of them      
}
