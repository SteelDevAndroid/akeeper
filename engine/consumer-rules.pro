# Le moteur natif rappelle les méthodes de Host par leur nom via JNI : R8 ne doit ni les renommer ni les retirer.
-keep interface com.akeeper.engine.NativeEngine$Host { *; }
-keepclassmembers class * implements com.akeeper.engine.NativeEngine$Host {
    boolean protect(int);
    int ownerUid(int, byte[], int, byte[], int);
}
# Points d'entrée JNI liés par nom (Java_com_akeeper_engine_NativeEngine_*) : classe et méthodes natives intactes.
-keepclasseswithmembernames,includedescriptorclasses class com.akeeper.engine.NativeEngine {
    native <methods>;
}
