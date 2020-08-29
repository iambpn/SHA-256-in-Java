import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

// only valid for 55 character long
public class SHA256 {
	private int hash [] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
	private int k [] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
					   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
					   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
					   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
					   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
					   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
					   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
					   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
	
	/* 
	 * Generate hash:
	 * step1: calling pre-processing function
	 * step2: breaking binary message returned from step1 into 512 bit chunk and for each chunk calling step3 and step4;
	 * Step3: calling SecondStage function
	 * Step4: calling compression function  
	 * step5: converting into hexadecimal and padding if necessary
	 * */
	private String generateHash(String msg) {
		
		String binaryMsg = preProcessing(msg);
		
		//breaking into 512 bit chunks
		String chunk[] = chunkOf(binaryMsg,512);
		
		//for each chunk
		for(int i=0;i!=chunk.length;i++) {
			int w[] =  secondStage(chunk[i]); //calling second stage
			compression(w); //calling compression function
		}
		
		//calculating digest
		String digest[] = new String [8];
		
		digest[0]=Integer.toHexString(this.hash[0]);
		digest[1]=Integer.toHexString(this.hash[1]);
		digest[2]=Integer.toHexString(this.hash[2]);
		digest[3]=Integer.toHexString(this.hash[3]);
		digest[4]=Integer.toHexString(this.hash[4]);
		digest[5]=Integer.toHexString(this.hash[5]);
		digest[6]=Integer.toHexString(this.hash[6]);
		digest[7]=Integer.toHexString(this.hash[7]);
		
		for(int i=0;i!= digest.length;i++) {
			if(digest[i].length()!=8) {
				digest[i] = padLeft(digest[i],8);
			}
		}
			
		return (digest[0]+digest[1]+digest[2]+digest[3]+digest[4]+digest[5]+digest[6]+digest[7]);
	}
	
	/* 
	 * Original message is passed to this function and preprocessing starts  
	 * (things we do in this function)
	 * Converting message into binary and adding 1
	 * padding 0
	 * appending original length of message in binary
	 * */
	private String preProcessing(String msg) {
		String binaryMsg="";
		
		// converting message into ASCII value 
		byte intMsg[] = msg.getBytes(StandardCharsets.UTF_8);
		String str = "";
		
		//converting message into binary
		for(int i=0; i!= intMsg.length;i++) {
			if((int)intMsg[i] < 0) {
				str = padLeft(Integer.toBinaryString((int)intMsg[i]+256),8); //(int)intMsg[i]+256 because to convert signed(-ve) byte into unsigned(+ve)
			}
			else {
				str = padLeft(Integer.toBinaryString((int)intMsg[i]),8); 
			}
			binaryMsg = binaryMsg+str;
		}
		
		int length = binaryMsg.length();
		binaryMsg = binaryMsg +"1";
		
		//padding zeros to right
		while(binaryMsg.length() % 512 != 448) {
			binaryMsg = binaryMsg + "0";
		}
		
		//adding length of original binary message(64 bit)
		binaryMsg = binaryMsg + padLeft(Integer.toBinaryString(length),64);

		return binaryMsg;
	}
	
	
	/*
	 *  512 bit message is passed into this function and 
	 *  breaking that message into 32 bit and adding it to new array of 64 index (it will only fill up to 0-15 index)
	 *  Generating 16 to 63 block from 0-15 using xor(^), rightrotate,right shift(>>>) and returning
	 *  */
	private int[] secondStage(String chunk) {
		int w[] = new int [64];
		int start=0;
		int end=32;
		
		// breaking into 32 bit and adding into array W
		for(int j=0;j!=16;j++) {
			String str = chunk.substring(start, end);
			start+=32;
			end+=32;
			w[j] = new BigInteger(str, 2).intValue();
		}
		
		// for remaining 16 to 64 spaces;
		int s1;
		int s0;
		for(int j=16; j!=64;j++) {
			s1= Integer.rotateRight(w[j-15], 7) ^ Integer.rotateRight(w[j-15], 18) ^ (w[j-15]>>>3);
			s0 = Integer.rotateRight(w[j-2], 17) ^ Integer.rotateRight(w[j-2], 19) ^ (w[j-2]>>>10);
			w[j]=w[j-16]+s0+w[j-7]+s1;
		}
		
		return w;
	}
	
	
	/* 
	 * 32 bit chunk array (w[]) is passed and compression function starts 
	 * compression function:
	 * Copy the hash function to new variable
	 * run compression loop which contain bunch of xor(^),and(&) and rightrotate operation and reassign the output 
	 * after completing loop. add original hash value and compressed values and assign it to hash variable
	 * */
	private void compression(int w[]) {
		
		//copying hash
		int a = this.hash[0];
		int b = this.hash[1];
		int c = this.hash[2];
		int d = this.hash[3];
		int e = this.hash[4];
		int f = this.hash[5];
		int g = this.hash[6];
		int h = this.hash[7];
		
		//compression loop
		int s1,ch,temp1,s0,maj,temp2;
		for(int j=0; j!=64; j++) {
			s1 = Integer.rotateRight(e,6) ^ Integer.rotateRight(e,11) ^ Integer.rotateRight(e,25);
			ch = (e & f) ^ ((~e) & g);
	        temp1 = h + s1 + ch + k[j] + w[j];
			s0 = Integer.rotateRight(a,2) ^ Integer.rotateRight(a,13) ^ Integer.rotateRight(a,22);
			maj = (a & b) ^ (a & c) ^ (b & c);
			temp2 = s0 +maj;
			
			h = g;
	        g = f;
	        f = e;
	        e = d + temp1;
	        d = c;
	        c = b;
	        b = a;
	        a = temp1 + temp2;
		}
		
		this.hash[0]=this.hash[0]+a;
		this.hash[1]=this.hash[1]+b;
		this.hash[2]=this.hash[2]+c;
		this.hash[3]=this.hash[3]+d;
		this.hash[4]=this.hash[4]+e;
		this.hash[5]=this.hash[5]+f;
		this.hash[6]=this.hash[6]+g;
		this.hash[7]=this.hash[7]+h;	
	}
	
	
	/*
	 *  padding on left side with 0 (works both padding or slicing)
	 *  takes string and total no of bit
	 *  returns array
	 *  */ 
	private String padLeft(String str,int bit) {
		return String.format("%"+bit+"s", str).replace(' ', '0');
	}
	
	
	/*
	 *  divide in equal no of chunks 
	 *  takes string and no of bit to break
	 *  returns array 
	 *  */
	private String[] chunkOf(String str,int bit) {
		String chunk[] = new String[str.length()/bit];
		int start=0;
		int end=bit;
		
		for(int i =0;i!=(str.length()/bit);i++) {
			chunk [i]= str.substring(start, end);
			start +=bit;
			end +=bit;
		}
		
		return chunk;
	}
	
	public String hashString(String text) {
		return generateHash(text);	
	}
}
