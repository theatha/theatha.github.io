
## Introduction
Hello everyone! Until seeing [this blog](https://n1ght-w0lf.github.io/tutorials/yara-for-config-extraction/) from [_n1ghtw0lf](https://twitter.com/_n1ghtw0lf), I did not know that we can use YARA rules for configuration extraction. He wrote a YARA rule for dotnet samples using dotnet and a custom module. Then, it is inspired me to do the same thing for other kinds of samples besides samples that are written in dotnet. However, I could not find any module that gets the data at the given offset. Thus, I decided to write my own helper. Also, I will give an example YARA rule that uses this module to extract the Danabot sample's configuration. 

##  The Situation 
YARA is mostly aimed at helping people to classify the samples. Typically, researchers would use YARA to detect patterns and identify the sample then will progress with the configuration extraction scripts if they found a known malware. If you insist to use YARA to extract some valuable information from the samples, there are some modules that can help. However, they are not much efficent for configuration extraction. For example, let's write a configuration extractor with YARA for the Danabot samples without modules. Try to understand YARA rule below; 
```php
import "console"
rule DanabotV1_Config_Extraction {
    meta:
        author = "Taha Y."
        danabot_samples = "https://github.com/f0wl/danaConfig"
    strings:
        $s1 = {4D0069006E00690049006E00690074003A004500780063006500700074000000}
    condition:
        $s1 and console.hex("[+] OFFSET ", @s1+214) 
            and console.log("[+] C2-#1:") and console.log("octet-1: ",uint8(@s1+214)) 
            and console.log("octet-2: ",uint8(@s1+215)) and console.log("octet-3: ",uint8(@s1+216)) and console.log("octet-4: ",uint8(@s1+217)) 
            and console.log("[+] C2-#2:") and console.log("octet-1: ",uint8(@s1+224)) 
            and console.log("octet-2: ",uint8(@s1+225)) and console.log("octet-3: ",uint8(@s1+226)) and console.log("octet-4: ",uint8(@s1+227)) 
            and console.log("[+] C2-#3:") and console.log("octet-1: ",uint8(@s1+234)) 
            and console.log("octet-2: ",uint8(@s1+235)) and console.log("octet-3: ",uint8(@s1+236)) and console.log("octet-4: ",uint8(@s1+237)) 
            and console.log("[+] C2-#4:") and console.log("octet-1: ",uint8(@s1+244)) 
            and console.log("octet-2: ",uint8(@s1+245)) and console.log("octet-3: ",uint8(@s1+246)) and console.log("octet-4: ",uint8(@s1+247)) 
}
```
![alt text](/assets/img/yara-conf/image1.png)

As you can see, the builtin functions could not much help. We are unable to output the data that is at the given offset properly. Also, we are unable to detect and show the strings that are in this sample directly. So, I do not think that anyone will find this method helpful. So, let's achieve these goals with the help of YARA modules!
##  YARA Modules 
Modules are the method YARA provides for extending its features. They allow you to define data structures and functions which can be used in your rules to express more complex conditions. Check [the docs](https://yara.readthedocs.io/en/stable/) for more information. 

##  Writing a YARA Module 
Modules are written in C and built into YARA as part of the compiling process. In order to create your own modules you must be familiar with the C programming language and how to configure and build YARA from source code. Check the docs for more information.    

YARA modules reside in libyara/modules, it’s recommended to use the module name as the file name for the source file. Then you should include the necessary libraries and defining the module name in the source code. 

```cpp
    #include <yara/modules.h>
    #include <inttypes.h>
        
    #define MODULE_NAME parseutils
```
###  Used Structures and Functions Explained 
If you check the source code [parseutils.c](https://github.com/theatha/YARA_for_config_extraction/blob/main/modules/parseutils/parseutils.c), you will see some structures and macros in use. I would like to explain what they are used for. 

```cpp
    /*
    	YR_SCAN_CONTEXT*: It is used to inspect the file or process memory being scanned.
    	YR_MEMORY_BLOCK*: Represents the memory block.
    	YR_MEMORY_BLOCK_ITERATOR*: Iterator for memory block.
    	YR_OBJECT*: Represents each object declared in the YARA module.
        define_function: Define your function with your desired function name and it's code.
        print_int_data: It is a function identifier.

    */
    // parseutils.print_int_data(offset,size)
    define_function(print_int_data){
        YR_SCAN_CONTEXT* context = yr_scan_context();
        YR_MEMORY_BLOCK* block;
        YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;
        YR_OBJECT* module = yr_module();
        /* 
           ... continues below
           ...
        */
    }
```

This function takes 2 parameters, <span style="color:green;">offset</span> and <span style="color:green;">size</span>. They can be defined like this: 

I used <span style="color:green;">foreach_memory_block</span>  and <span style="color:green;">fetch_data</span> to get data according to the given offset and size. 

```cpp
    // define_function(print_int_data) continues
        // foreach_memory_block macro allows iterating over data sliced into blocks.
        foreach_memory_block(iterator, block)
        {
            // fetch_data returns a pointer to the block's data.
            // Each data in the block comes to the block_data
            // variable and is thrown into the data array.
            const uint8_t* block_data = block->fetch_data(block);
            int t = 0;
            for (size_t i = offset_0; i<offset_0+size; i++)
            {
            uint8_t c = *(block_data + i);
            data[t] = c;
            t++;
            }
        }
        char str[size];
        int index = 0;
        // convert the data arr to desired char arr 
        for(int i=0; i< size; i++)
          index += sprintf(&str[index], "%d ", data[i]);
        
        // set desired output with set_string
        yr_set_string(str,module,"str");
        // return the char arr
        return_string(str);
    }
```

Then, running included ["build.sh"](https://github.com/VirusTotal/yara/blob/master/build.sh) script in YARA will be compiled with this newly created module. 
 
## The Action

Let's see [parseutils](https://github.com/theatha/YARA_for_config_extraction/tree/main/modules) in action!

###  Brief Summary of Danabot's Configuration Structure 
![alt text](/assets/img/yara-conf/image2.png)
![alt text](/assets/img/yara-conf/image3.png)

Let's write a new YARA rule that actually <span style="color:green;">outputs</span>  helpful information this time. 

```php
    import "console"
    import "parseutils"
    rule danabot_config_extractor {
    	meta:
    		author = "Taha Y."
    		danabot_samples = "https://github.com/f0wl/danaConfig"
    	strings:
    		$s1 = {4D0069006E00690049006E00690074003A004500780063006500700074000000}
    		$s2 = {2E6F6E696F6E} //.onion
    	condition:
    		$s1 and console.hex("OFFSET : ",@s1+224) and 
    		 console.log("C2-ip1: ",parseutils.print_int_data(@s1+214,4)) and
    		 console.log("C2-ip2: ",parseutils.print_int_data(@s1+224,4)) and
    		 console.log("C2-ip3: ",parseutils.print_int_data(@s1+234,4)) and
    		 console.log("C2-ip4: ",parseutils.print_int_data(@s1+244,4)) and
    		 console.log("TOR: ",parseutils.print_string_data(@s2-56,62))
    }
```
![alt text](/assets/img/yara-conf/image4.png)

##  The Conclusion 
Although the YARA project is mainly used for detection and identifying malware samples, I managed to achieve another goal, which is extracting valuable information. Deep deep down, far far in, I feel that this effort is redundant yet shows how much YARA is flexible.

You can find mentioned resources and one extra yara rule that extracts information from another Danabot variant in ["YARA_for_config_extraction"](https://github.com/theatha/YARA_for_config_extraction) repository. If you want to discuss or ask me something, you can reach me from [twitter](https://twitter.com/_theatha).