# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src/build

# Include any dependencies generated for this target.
include CMakeFiles/eakv.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/eakv.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/eakv.dir/flags.make

# Object files for target eakv
eakv_OBJECTS =

# External object files for target eakv
eakv_EXTERNAL_OBJECTS = \
"/home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src/build/CMakeFiles/eakv_obj.dir/ctrl.c.o" \
"/home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src/build/CMakeFiles/eakv_obj.dir/dllmain.c.o" \
"/home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src/build/CMakeFiles/eakv_obj.dir/e_akv_err.c.o" \
"/home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src/build/CMakeFiles/eakv_obj.dir/key.c.o" \
"/home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src/build/CMakeFiles/eakv_obj.dir/rsa.c.o" \
"/home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src/build/CMakeFiles/eakv_obj.dir/ec.c.o" \
"/home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src/build/CMakeFiles/eakv_obj.dir/base64.c.o" \
"/home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src/build/CMakeFiles/eakv_obj.dir/curl.c.o" \
"/home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src/build/CMakeFiles/eakv_obj.dir/pch.c.o" \
"/home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src/build/CMakeFiles/eakv_obj.dir/log.c.o"

e_akv.so: CMakeFiles/eakv_obj.dir/ctrl.c.o
e_akv.so: CMakeFiles/eakv_obj.dir/dllmain.c.o
e_akv.so: CMakeFiles/eakv_obj.dir/e_akv_err.c.o
e_akv.so: CMakeFiles/eakv_obj.dir/key.c.o
e_akv.so: CMakeFiles/eakv_obj.dir/rsa.c.o
e_akv.so: CMakeFiles/eakv_obj.dir/ec.c.o
e_akv.so: CMakeFiles/eakv_obj.dir/base64.c.o
e_akv.so: CMakeFiles/eakv_obj.dir/curl.c.o
e_akv.so: CMakeFiles/eakv_obj.dir/pch.c.o
e_akv.so: CMakeFiles/eakv_obj.dir/log.c.o
e_akv.so: CMakeFiles/eakv.dir/build.make
e_akv.so: /usr/lib/x86_64-linux-gnu/libcrypto.so
e_akv.so: /usr/lib/x86_64-linux-gnu/libssl.so
e_akv.so: /usr/lib/x86_64-linux-gnu/libcurl.so
e_akv.so: /usr/lib/x86_64-linux-gnu/libjson-c.so
e_akv.so: CMakeFiles/eakv.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Linking C shared library e_akv.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/eakv.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/eakv.dir/build: e_akv.so

.PHONY : CMakeFiles/eakv.dir/build

CMakeFiles/eakv.dir/requires:

.PHONY : CMakeFiles/eakv.dir/requires

CMakeFiles/eakv.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/eakv.dir/cmake_clean.cmake
.PHONY : CMakeFiles/eakv.dir/clean

CMakeFiles/eakv.dir/depend:
	cd /home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src /home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src /home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src/build /home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src/build /home/azureuser/repos/AzureKeyVaultManagedHSMEngine/src/build/CMakeFiles/eakv.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/eakv.dir/depend

