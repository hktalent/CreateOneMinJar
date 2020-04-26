package com._51pwn.hktalent;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Iterator;
import java.util.Vector;

public class CreatJar {

	private static String szPath="/tmp/51pwn_com"+System.currentTimeMillis() + "/";
	public static byte[] toByteArray(InputStream in) throws Exception {

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		byte[] buffer = new byte[1024 * 4];
		int n = 0;
		while ((n = in.read(buffer)) != -1) {
			out.write(buffer, 0, n);
		}
		return out.toByteArray();
	}

	public static String bytesToHexString(byte[] bArray, int length) {
		StringBuffer sb = new StringBuffer(length);
		String sTemp;
		for (int i = 0; i < length; i++) {
			sTemp = Integer.toHexString(0xFF & bArray[i]);
			if (sTemp.length() < 2)
				sb.append(0);
			sb.append(sTemp.toUpperCase());
		}
		return sb.toString();
	}

	public static void getHexStr(String szName, ClassLoader cl) throws Exception {
		if(-1 < szName.indexOf(CreatJar.class.getName()))return;
		String szNm = szName.replace('.', '/') + ".class";
		InputStream in = cl.getResourceAsStream(szNm);
		byte[] data = toByteArray(in);
		in.close();
		File f = new File(szPath+ szNm);
		File fP1 = new File(f.getParent());
		if (!fP1.exists()) {
			fP1.mkdirs();
		}
		FileOutputStream fos = new FileOutputStream(f);
		fos.write(data);
		fos.flush();
		fos.close();
		System.out.print(szName + " " + data.length+"\r");
	}

	
	private static void getClassXX(String s, ClassLoader cl) {
		try {
			s = s.split(" ")[1];
			getHexStr(s, cl);
		} catch (Exception e) {
//			e.printStackTrace();
		}
	}

	private static void write(byte[] a) {
		try {
			if (null != a && 0 < a.length) {
				System.out.write(a);
			}
		} catch (Exception e) {
		}
	}

	private static void print(String s) {
		write(s.getBytes());
	}

	private static Iterator list(ClassLoader CL)
			throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
		Class CL_class = CL.getClass();
		while (CL_class != java.lang.ClassLoader.class) {
			CL_class = CL_class.getSuperclass();
		}
		java.lang.reflect.Field ClassLoader_classes_field = CL_class.getDeclaredField("classes");
		ClassLoader_classes_field.setAccessible(true);
		Vector classes = (Vector) ClassLoader_classes_field.get(CL);
		return classes.iterator();
	}
	public static void recursiveDelete(File file) {
        if (!file.exists())
            return;
        if (file.isDirectory()) {
        	File []fs = file.listFiles();
        	
            for (int i = 0; i < fs.length ;i++) {
                recursiveDelete(fs[i]);
            }
        }
        file.deleteOnExit();
    }
	/*
	 * jar uf hktalent_51pwn_com.jar  weblogic/iiop/IOPProfile.class
	 * */
	public static void main(String[] args) {
		File f1=new File(szPath);
		try {
		f1.mkdirs();
		ClassLoader myCL = Thread.currentThread().getContextClassLoader();
//		ClassLoader myCL1 =myCL; 
		while (myCL != null) {
			for (Iterator iter = list(myCL); iter.hasNext();) {
				String xx = iter.next().toString();
				getClassXX(xx, myCL);
			}
			if(myCL == myCL.getParent())break;
			myCL = myCL.getParent();
		}
//		getClassXX("weblogic.rmi.internal.PhantomRef", myCL1);
		
		} catch (Throwable e) {
			e.printStackTrace();
		}
		finally {
			
			File f2 = new File(".");
			try {
//				_12.1.3.0
//				String s1 = "/Users/0x101/safe/mytools_10012106/dr0op_WeblogicScan/tools/51pwn_com_CVE_2020_2551_12.1.3.0.0.jar";
				String jarName = System.getenv("jarName");
				String s1 = f2.getCanonicalPath() + File.separator + "51pwn.com.jar";
				if(null != jarName)
					s1=jarName;
				new File(s1).delete();
//				-M "+args[0]+"
				String []a = {"/bin/sh","-c","jar  -cvf "+s1 + " -C "+szPath+" . ;rm -rf "+szPath};
				if(-1 < System.getProperty("os.name").toLowerCase().indexOf("window"))
				{
					a[0]="cmd.exe";
					a[1]="/c";
				}
				java.lang.Runtime.getRuntime().exec(a);
				System.out.println("\r\n"+s1);
				System.out.println(a[2]);
			} catch (Exception e) {
				e.printStackTrace();
			}
//			recursiveDelete(f1);
		}
	}

}
