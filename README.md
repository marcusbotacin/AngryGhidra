# (My) AngryGhidra

This is my version of the AngryGhidra plugin. Check out the original plugin [here](https://github.com/Nalen98/AngryGhidra)

I created this version to be used along [MalVerse](https://github.com/marcusbotacin/MalVerse).

The idea was to output the output of my [patched angr version](https://github.com/marcusbotacin/angr). Since I'm too lazy to create a plugin by myself, I reused this very nice one.

This plugin has two components, a Java frontend for ghidra and a Python backend for angr. If you look into *AngryGhidraProvider.java* you notice that they are integrated via processes.

```Java
 public void runAngr(String script_path, String angrfile_path) {
        ProcessBuilder pb = new ProcessBuilder("python3", script_path, angrfile_path);
```

Since I was interested only in modifying the angr part, I just updated the *angryghidra_script/angryghidra.py* script. To understand the modifications, check out the MalVerse repository. 

Notice: My modifications break the original plugin features.





