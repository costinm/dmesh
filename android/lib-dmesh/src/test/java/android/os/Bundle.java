package android.os;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

/** Host-only stand-in for the Bundle operations exercised by codec tests. */
public class Bundle {
    public static final Bundle EMPTY = new Bundle();
    private final HashMap<String, Object> values = new HashMap<>();
    public Bundle() { }
    public Bundle(Bundle other) { values.putAll(other.values); }
    public Set<String> keySet() { return values.keySet(); }
    public Object get(String key) { return values.get(key); }
    public boolean containsKey(String key) { return values.containsKey(key); }
    public boolean isEmpty() { return values.isEmpty(); }
    public String getString(String key) { return (String) values.get(key); }
    public Bundle getBundle(String key) { return (Bundle) values.get(key); }
    public void putString(String key, String v) { values.put(key, v); }
    public void putBoolean(String key, boolean v) { values.put(key, v); }
    public void putInt(String key, int v) { values.put(key, v); }
    public void putLong(String key, long v) { values.put(key, v); }
    public void putFloat(String key, float v) { values.put(key, v); }
    public void putDouble(String key, double v) { values.put(key, v); }
    public void putByteArray(String key, byte[] v) { values.put(key, v); }
    public void putBundle(String key, Bundle v) { values.put(key, v); }
    public void putStringArrayList(String key, ArrayList<String> v) { values.put(key, v); }
}
