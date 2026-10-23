# Le moteur natif rappelle les méthodes de Host par leur nom via JNI : R8 ne doit ni les renommer ni les retirer.
-keep interface com.akeeper.engine.NativeEngine$Host { *; }
-keepclassmembers class * implements com.akeeper.engine.NativeEngine$Host {
    boolean protect(int);
    int ownerUid(int, byte[], int, byte[], int);
}
