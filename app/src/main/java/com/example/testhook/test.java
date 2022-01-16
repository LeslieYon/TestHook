package com.example.testhook;

import android.util.Base64;
import android.util.Log;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.math.BigInteger;
import java.security.MessageDigest;

public class test implements IXposedHookLoadPackage {

    public static String byteArray2HexString(byte[] bytes) {
        char[] HEX = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        char[] str = new char[bytes.length * 2];
        int j = 0;
        for (byte ele : bytes) {
            str[j++] = HEX[(ele & 0xF0) >>> 4]; //无符号左移
            str[j++] = HEX[(ele & 0x0F)];
        }
        return String.valueOf(str);
    }

    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
        //XposedBridge.log("Loaded app: " + lpparam.packageName);
        //Log.d("LeslieYon", "Hook...");

        {
            if (lpparam.packageName.equals("com.google.android.gms")) return;
            if (lpparam.packageName.equals("com.android.vending")) return;
            if (lpparam.packageName.equals("com.google.android.gsf")) return;
            if (lpparam.packageName.equals("com.google.android.gsf.login")) return;
        }

        try {
            XposedBridge.hookAllMethods(XposedHelpers.findClass("java.security.MessageDigest", lpparam.classLoader),
                    "digest",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            Log.e("LeslieYon", "Stack:", new Throwable("stack dump"));
                            MessageDigest md = (MessageDigest) param.thisObject;
                            String algoritm = md.getAlgorithm();
                            if (param.args.length >= 1) {
                                byte[] params = (byte[]) param.args[0];
                                String data = new String(params);
                                String dataHex = byteArray2HexString(params);
                                Log.d("LeslieYon", algoritm + " data: " + data);
                                Log.d("LeslieYon", algoritm + " dataHex: " + dataHex);
                            }
                            byte[] res = (byte[]) param.getResult();
                            String resHex = byteArray2HexString(res);
                            String resBase64 = Base64.encodeToString(res, 0);
                            Log.d("LeslieYon", algoritm + " resultHex: " + resHex);
                            Log.d("LeslieYon", algoritm + " resultBase64: " + resBase64);
                            Log.d("LeslieYon", "=======================================================================");
                        }
                    });
        } catch (Exception e) {
            Log.e("LeslieYon", "MessageDigest.digest Error: " + e.getMessage());
        }

        try {
            XposedBridge.hookAllMethods(XposedHelpers.findClass("java.security.MessageDigest", lpparam.classLoader),
                    "update",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Log.e("LeslieYon", "Stack:", new Throwable("stack dump"));
                            MessageDigest md = (MessageDigest) param.thisObject;
                            String algoritm = md.getAlgorithm();
                            int offset = 0;
                            int len = 0;
                            byte[] params = (byte[]) param.args[0];
                            if (param.args.length != 3) {
                                offset = 0;
                                len = params.length;
                            } else {
                                offset = (Integer) param.args[1];
                                len = (Integer) param.args[2];
                            }
                            byte[] input = new byte[len];
                            System.arraycopy(params, offset, input, 0, len);
                            String data = new String(input);
                            String dataHex = byteArray2HexString(input);
                            Log.d("LeslieYon", algoritm + " update data: " + data);
                            Log.d("LeslieYon", algoritm + " update dataHex: " + dataHex);
                            Log.d("LeslieYon", "=======================================================================");
                        }
                    });
        } catch (Exception e) {
            Log.e("LeslieYon", "MessageDigest.update Error: " + e.getMessage());
        }

        try {
            XposedBridge.hookAllMethods(XposedHelpers.findClass("javax.crypto.Mac", lpparam.classLoader),
                    "doFinal",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            Log.e("LeslieYon", "Stack:", new Throwable("stack dump"));
                            if (param.args.length == 2) return;
                            Mac mac = (Mac) param.thisObject;
                            String algoritm = mac.getAlgorithm();
                            if (param.args.length == 1) {
                                byte[] params = (byte[]) param.args[0];
                                String data = new String(params);
                                String dataHex = byteArray2HexString(params);
                                Log.d("LeslieYon", algoritm + " data: " + data);
                                Log.d("LeslieYon", algoritm + " dataHex: " + dataHex);
                            }
                            byte[] res = (byte[]) param.getResult();
                            String resHex = byteArray2HexString(res);
                            String resBase64 = Base64.encodeToString(res, 0);
                            Log.d("LeslieYon", algoritm + " resultHex: " + resHex);
                            Log.d("LeslieYon", algoritm + " resultBase64: " + resBase64);
                            Log.d("LeslieYon", "=======================================================================");
                        }
                    });
        } catch (Exception e) {
            Log.e("LeslieYon", "crypto.Mac.doFinal Error: " + e.getMessage());
        }

        try {
            XposedBridge.hookAllConstructors(XposedHelpers.findClass("javax.crypto.spec.SecretKeySpec", lpparam.classLoader),
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Log.e("LeslieYon", "Stack:", new Throwable("stack dump"));
                            byte[] secretkey = (byte[]) param.args[0];
                            int offset = 0;
                            int size = 0;
                            String algoritm = null;
                            if (param.args.length != 2) {
                                offset = (Integer) param.args[1];
                                size = (Integer) param.args[2];
                                algoritm = (String) param.args[3];
                            } else {
                                size = secretkey.length;
                                algoritm = (String) param.args[1];
                            }
                            byte[] keybyte = new byte[size];
                            System.arraycopy(secretkey, offset, keybyte, 0, size);
                            String keyHex = byteArray2HexString(keybyte);
                            String keyBase64 = Base64.encodeToString(keybyte, 0);
                            Log.d("LeslieYon", algoritm + " SecretKey: " + new String(keybyte));
                            Log.d("LeslieYon", algoritm + " SecretKeyHex: " + keyHex);
                            Log.d("LeslieYon", algoritm + " SecretKeyBase64: \n" + keyBase64);
                            Log.d("LeslieYon", "=======================================================================");
                        }
                    });
        } catch (Exception e) {
            Log.e("LeslieYon", "SecretKeySpec Error: " + e.getMessage());
        }

        try {
            XposedBridge.hookAllConstructors(XposedHelpers.findClass("javax.crypto.spec.DESKeySpec", lpparam.classLoader),
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Log.e("LeslieYon", "Stack:", new Throwable("stack dump"));
                            byte[] desKey = new byte[8];
                            byte[] deskeybyte = (byte[]) param.args[0];
                            int offset = 0;
                            if (param.args.length != 1)
                                offset = (Integer) param.args[1];
                            System.arraycopy(deskeybyte, offset, desKey, 0, 8);
                            String keyHex = byteArray2HexString(desKey);
                            String keyBase64 = Base64.encodeToString(desKey, 0);
                            Log.d("LeslieYon", "DESKey: " + new String(desKey));
                            Log.d("LeslieYon", "DESKeyHex: " + keyHex);
                            Log.d("LeslieYon", "DESKeyBase64: \n" + keyBase64);
                            Log.d("LeslieYon", "=======================================================================");
                        }
                    });
        } catch (Exception e) {
            Log.e("LeslieYon", "DESKeySpec Error: " + e.getMessage());
        }

        try {
            XposedBridge.hookAllConstructors(XposedHelpers.findClass("javax.crypto.spec.IvParameterSpec", lpparam.classLoader),
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Log.e("LeslieYon", "Stack:", new Throwable("stack dump"));
                            byte[] ivbyte = (byte[]) param.args[0];
                            int offset = 0;
                            int size = 0;
                            if (param.args.length != 1) {
                                offset = (Integer) param.args[1];
                                size = (Integer) param.args[2];
                            } else size = ivbyte.length;
                            byte[] iv = new byte[size];
                            System.arraycopy(ivbyte, offset, iv, 0, size);
                            String IVHex = byteArray2HexString(iv);
                            String IVBase64 = Base64.encodeToString(iv, 0);
                            Log.d("LeslieYon", "IvParameter: " + new String(iv));
                            Log.d("LeslieYon", "IvParameterHex: " + IVHex);
                            Log.d("LeslieYon", "IvParameterBase64: \n" + IVBase64);
                            Log.d("LeslieYon", "=======================================================================");
                        }
                    });
        } catch (Exception e) {
            Log.e("LeslieYon", "IvParameterSpec Error: " + e.getMessage());
        }

        try {
            XposedBridge.hookAllMethods(XposedHelpers.findClass("javax.crypto.Cipher", lpparam.classLoader),
                    "doFinal",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            Log.e("LeslieYon", "Stack:", new Throwable("stack dump"));
                            if (param.args.length != 0 && param.args.length != 1 && param.args.length != 3) return;
                            Cipher cipher = (Cipher) param.thisObject;
                            String algoritm = cipher.getAlgorithm();
                            byte[] dataAll = (byte[]) param.args[0];
                            if (param.args.length == 3) {
                                int offset = (Integer) param.args[1];
                                int size = (Integer) param.args[2];
                                byte[] dataByte = new byte[size];
                                System.arraycopy(dataAll, offset, dataByte, 0, size);
                                Log.d("LeslieYon", algoritm + " data: " + new String(dataByte));
                                Log.d("LeslieYon", algoritm + " dataHex: " + byteArray2HexString(dataByte));
                                Log.d("LeslieYon", algoritm + " dataBase64: \n" + Base64.encodeToString(dataByte, 0));
                            } else if (param.args.length == 1) {
                                Log.d("LeslieYon", algoritm + " data: " + new String(dataAll));
                                Log.d("LeslieYon", algoritm + " dataHex: " + byteArray2HexString(dataAll));
                                Log.d("LeslieYon", algoritm + " dataBase64: \n" + Base64.encodeToString(dataAll, 0));
                            }
                            byte[] res = (byte[]) param.getResult();
                            String resHex = byteArray2HexString(res);
                            String resBase64 = Base64.encodeToString(res, 0);
                            Log.d("LeslieYon", algoritm + " resultHex: " + resHex);
                            Log.d("LeslieYon", algoritm + " resultBase64: \n" + resBase64);
                            Log.d("LeslieYon", "=======================================================================");
                        }
                    });
        } catch (Exception e) {
            Log.e("LeslieYon", "crypto.Cipher.doFinal Error: " + e.getMessage());
        }

        try {
            XposedBridge.hookAllConstructors(XposedHelpers.findClass("javax.crypto.spec.DESedeKeySpec", lpparam.classLoader),
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Log.e("LeslieYon", "Stack:", new Throwable("stack dump"));
                            byte[] keybyte = (byte[]) param.args[0];
                            int offset = 0;
                            if (param.args.length != 1)
                                offset = (Integer) param.args[1];
                            byte[] desedeKey = new byte[24];
                            System.arraycopy(keybyte, offset, desedeKey, 0, 24);
                            String desedeKeyHex = byteArray2HexString(desedeKey);
                            String desedeKeyBase64 = Base64.encodeToString(desedeKey, 0);
                            Log.d("LeslieYon", "3DESKey: " + new String(desedeKey));
                            Log.d("LeslieYon", "3DESKeyHex: " + desedeKeyHex);
                            Log.d("LeslieYon", "3DESKeyBase64: \n" + desedeKeyBase64);
                            Log.d("LeslieYon", "=======================================================================");
                        }
                    });
        } catch (Exception e) {
            Log.e("LeslieYon", "DESedeKeySpec Error: " + e.getMessage());
        }

        try {
            XposedBridge.hookAllConstructors(XposedHelpers.findClass("java.security.spec.X509EncodedKeySpec", lpparam.classLoader),
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Log.e("LeslieYon", "Stack:", new Throwable("stack dump"));
                            byte[] keybyte = (byte[]) param.args[0];
                            String keybyteBase64 = Base64.encodeToString(keybyte, 0);
                            String keybyteHex = byteArray2HexString(keybyte);
                            Log.d("LeslieYon", "X509KeyHex: " + keybyteHex);
                            Log.d("LeslieYon", "X509KeyBase64: \n" + keybyteBase64);
                            Log.d("LeslieYon", "=======================================================================");
                        }
                    });
        } catch (Exception e) {
            Log.e("LeslieYon", "X509EncodedKeySpec Error: " + e.getMessage());
        }

        try {
            XposedBridge.hookAllConstructors(XposedHelpers.findClass("java.security.spec.PKCS8EncodedKeySpec", lpparam.classLoader),
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Log.e("LeslieYon", "Stack:", new Throwable("stack dump"));
                            byte[] keybyte = (byte[]) param.args[0];
                            String keybyteBase64 = Base64.encodeToString(keybyte, 0);
                            String keybyteHex = byteArray2HexString(keybyte);
                            Log.d("LeslieYon", "PKCS8KeyHex: " + keybyteHex);
                            Log.d("LeslieYon", "PKCS8KeyBase64: \n" + keybyteBase64);
                            Log.d("LeslieYon", "=======================================================================");
                        }
                    });
        } catch (Exception e) {
            Log.e("LeslieYon", "PKCS8EncodedKeySpec Error: " + e.getMessage());
        }

        try {
            XposedBridge.hookAllConstructors(XposedHelpers.findClass("java.security.spec.RSAPublicKeySpec", lpparam.classLoader),
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Log.e("LeslieYon", "Stack:", new Throwable("stack dump"));
                            BigInteger N = (BigInteger) param.args[0];
                            BigInteger E = (BigInteger) param.args[1];
                            Log.d("LeslieYon", "RSAPublicKey N : " + N.toString(16));
                            Log.d("LeslieYon", "RSAPublicKey E : " + E.toString(16));
                            Log.d("LeslieYon", "=======================================================================");
                        }
                    });
        } catch (Exception e) {
            Log.e("LeslieYon", "RSAPublicKeySpec Error: " + e.getMessage());
        }

        try {
            XposedBridge.hookAllConstructors(XposedHelpers.findClass("java.security.spec.RSAPrivateKeySpec", lpparam.classLoader),
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Log.e("LeslieYon", "Stack:", new Throwable("stack dump"));
                            BigInteger N = (BigInteger) param.args[0];
                            BigInteger D = (BigInteger) param.args[1];
                            Log.d("LeslieYon", "RSAPrivateKey N : " + N.toString(16));
                            Log.d("LeslieYon", "RSAPrivateKey D : " + D.toString(16));
                            Log.d("LeslieYon", "=======================================================================");
                        }
                    });
        } catch (Exception e) {
            Log.e("LeslieYon", "RSAPrivateKeySpec Error: " + e.getMessage());
        }
    }
}
