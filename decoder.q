\d .pcap

// size of headers in bytes
globheader: 24;
packetheader: 16;


buildtable:{[file]
 data:1_ last each {[n] // initial x and byte cut points removed from array list to make table
  filebytesize:count n;

  // iterates through packets, extracting data 
  gettablerow[n;]\[{y>(first x[0])+40}[;filebytesize];(),0]
  } read1 file;

 data
 }


gettablerow:{[n;x] 
   // table row data
   
   time: gettime[n;x];
   length: 1 sv n[x[0] + 36 40]; 
   data: (length - 68)#(globheader+packetheader+68+x[0]) _ n;
   flags: getflags[n;x];
   len: count data;
 
   src: getips[28;n;x];
   dest: getips[32;n;x];

   srcport: getports[36;n;x];
   destport: getports[38;n;x];
   
   seq: getinfo[40;n;x;"i";4;4294967296];
   ack: getinfo[44;n;x;"i";4;4294967296];
   tsval: getinfo[60;n;x;"i";4;4294967296];
   tsecr: getinfo[64;n;x;"i";4;4294967296];
   win: getinfo[50;n;x;"h";2;65536];
   
   // dict of protocol code conversions 
   codes:(enlist 6)!(enlist `TCP);
   protocol: $[getcode[n;x] in key codes; codes[getcode[n;x]]; getcode[n;x]];

   // array containing starting point for next byte and dictionary of data for current packet
   (x[0] + length + 16;`time`src`dest`srcport`destport`protocol`flags`seq`ack`win`tsval`tsecr`length`len`data!(time;src;dest;srcport;destport;protocol;flags;seq;ack;win;tsval;tsecr;length;len;data))
   }


gettime:{[n;x] linuxtokdbtime ("iiii";4 4 4 4)1:16#(24+x[0]) _ n }

linuxtokdbtime:{
 // converts time in global header to nanoseconds then accounts for difference in epoch dates in kdb and linux
 "p"$1000*x[1]+1000000*x[0]-10957*86400
 }

getflags:{[n;x]
 bools: raze "b"$ 2 vs 1#(24+16+49+x[0]) _ n;
 `CWR`ECE`URG`ACK`PSH`RST`SYN`FIN where ((8 - count bools)#0b), bools
 }

getcode:{[n;x]
 // code number is stored at 25th byte of packet
 ("i"$1#(globheader+packetheader+25+x[0]) _ n)[0]
 }

getinfo:{[byte;n;x;converttype;bytechunk;typemax]
 // byte is starting point, bytechunk is amount taken
 // mod value is 1 + max value of typemax
 ((enlist bytechunk;enlist converttype)1: bytechunk #(globheader+packetheader+byte+x[0]) _ n) mod typemax
 };

getips:{[byte;n;x]
 `$"." sv ' string 4 cut "i"$4#(globheader+packetheader+byte+x[0]) _ n
 };

getports: {[byte;n;x]
 // mod value is the max value of shorts
 `$ string ((enlist 2;enlist "h")1: 2#(globheader+packetheader+byte+x[0]) _ n) mod 65536
 };

