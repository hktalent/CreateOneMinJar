package com._51pwn.hktalent;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Iterator;
import java.util.Vector;

public class CreatJar {

	private static String szPath = "/tmp/51pwn_com" + System.currentTimeMillis() + "/";

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
		if (-1 < szName.indexOf(CreatJar.class.getName()))
			return;
		String szNm = szName.replace('.', '/') + ".class";
		InputStream in = cl.getResourceAsStream(szNm);
		byte[] data = toByteArray(in);
		in.close();
		File f = new File(szPath + szNm);
		File fP1 = new File(f.getParent());
		if (!fP1.exists()) {
			fP1.mkdirs();
		}
		wtFile(f, data);
		System.out.print(szName + " " + data.length + "\r");
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

	/**
	 * delete tmp files
	 * 
	 * @param file
	 */
	public static void recursiveDelete(File file) {
		if (!file.exists())
			return;
		if (file.isDirectory()) {
			File[] fs = file.listFiles();

			for (int i = 0; i < fs.length; i++) {
				recursiveDelete(fs[i]);
			}
		}
		file.deleteOnExit();
	}

	public static void creatJar() {
		File f1 = new File(szPath);
		try {
			f1.mkdirs();
			ClassLoader myCL = Thread.currentThread().getContextClassLoader();
//	ClassLoader myCL1 =myCL; 
			while (myCL != null) {
				for (Iterator iter = list(myCL); iter.hasNext();) {
					String xx = iter.next().toString();
					getClassXX(xx, myCL);
				}
				if (myCL == myCL.getParent())
					break;
				myCL = myCL.getParent();
			}
//	getClassXX("weblogic.rmi.internal.PhantomRef", myCL1);

		} catch (Throwable e) {
			e.printStackTrace();
		} finally {

			File f2 = new File(".");
			try {
//			_12.1.3.0
//			String s1 = "/Users/0x101/safe/mytools_10012106/dr0op_WeblogicScan/tools/51pwn_com_CVE_2020_2551_12.1.3.0.0.jar";
				String jarName = System.getenv("jarName");
				String s1 = f2.getCanonicalPath() + File.separator + "51pwn.com.jar";
				if (null != jarName)
					s1 = jarName;
				jarNamePath = s1;
				new File(s1).delete();
//			-M "+args[0]+"
//			jar cvmf MANIFEST.MF
				String[] a = { "/bin/sh", "-c", "jar  -cvf " + s1 + " -C " + szPath + " . ;rm -rf " + szPath };
				if (-1 < System.getProperty("os.name").toLowerCase().indexOf("window")) {
					a[0] = "cmd.exe";
					a[1] = "/c";
				}
				java.lang.Runtime.getRuntime().exec(a);
				System.out.println("\r\n" + s1);
				System.out.println(a[2]);
			} catch (Exception e) {
				e.printStackTrace();
			}
//		recursiveDelete(f1);
		}
	}

	private static String jarNamePath = null;

	private static void wtFile(File f, byte[] data) {
		try {
			FileOutputStream fos = new FileOutputStream(f);
			fos.write(data);
			fos.flush();
			fos.close();
		} catch (Exception e) {
			log(e);
		}
	}

	private static void log(Throwable e) {
		e.printStackTrace();
	}

	private static String _404ClassList = "_404ClassList.txt";

	private static void load4040ClassList() {
		try {
			byte[] x = new byte[4096];
			ByteArrayOutputStream bo = new ByteArrayOutputStream();
			FileInputStream o = new FileInputStream(new File(_404ClassList));
			int j = 0;
			while (0 < (j = o.read(x, 0, 4096))) {
				bo.write(x, 0, j);
			}
			o.close();
			x = bo.toByteArray();
			String[] a1 = new String(x).split("\n");
			for (int i = 0; i < a1.length; i++) {
				try {
					Class.forName(a1[i]);
				} catch (Throwable e) {
					log(e);
				}
			}
		} catch (Exception e) {
			log(e);
		}
	}

	/**
	 * 1、记录到文本文件，方便下次打包提前加载 2、更新到当前jar，并进入下轮测试
	 * 
	 * @param s
	 */
	private static void cacheLoadCls(String s,String[] args) {
		wtFile(new File(_404ClassList), (s + "\n").getBytes());
		getClassXX(s, Thread.currentThread().getContextClassLoader());
		try {
			Process p = java.lang.Runtime.getRuntime().exec(new String[] { "jar", "uf", jarNamePath,s.replaceAll("\\.", "/")+".class" });
			p.waitFor();
			p.destroy();
			// test next
			testJar(args);
		} catch (Exception e) {
			log(e);
		}
	}

	public static void testJar(String[] args) {
		try {
			Process p = java.lang.Runtime.getRuntime().exec(new String[] { "java", "-jar", jarNamePath });
			InputStream fis = p.getInputStream();
			// 用一个读输出流类去读
			InputStreamReader isr = new InputStreamReader(fis);
			// 用缓冲器读行
			BufferedReader br = new BufferedReader(isr);
			String line = null;
			String[] a = null, x = { "java.lang.NoClassDefFoundError:", "java.lang.ClassNotFoundException:" };
			// 直到读完为止
			while ((line = br.readLine()) != null) {
				if (-1 < line.indexOf(x[0]))
					a = line.split(x[0]);
				else if (-1 < line.indexOf(x[1]))
					a = line.split(x[1]);
				if (null != a && 2 == a.length) {
					System.out.println("now retry test for " + line);
					cacheLoadCls(a[1].trim().replaceAll("\\/", "."),args);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/*
	 * jar uf hktalent_51pwn_com.jar weblogic/iiop/IOPProfile.class
	 */
	public static void main(String[] args) {
		load4040ClassList();
		creatJar();
		testJar(args);
	}

}
