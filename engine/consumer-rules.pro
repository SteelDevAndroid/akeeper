# Le moteur natif rappelle Host.protect(int) par son nom via JNI : R8 ne doit ni le renommer ni le retirer.
-keep interface com.akeeper.engine.NativeEngine$Host { *; }
-keepclassmembers class * implements com.akeeper.engine.NativeEngine$Host {
    boolean protect(int);
}
