# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.17

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

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
CMAKE_COMMAND = /usr/local/clion-2020.2/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /usr/local/clion-2020.2/bin/cmake/linux/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/anti-shadowsocksR

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/anti-shadowsocksR/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/anti_shadowsocksR.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/anti_shadowsocksR.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/anti_shadowsocksR.dir/flags.make

CMakeFiles/anti_shadowsocksR.dir/main.cpp.o: CMakeFiles/anti_shadowsocksR.dir/flags.make
CMakeFiles/anti_shadowsocksR.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/anti-shadowsocksR/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/anti_shadowsocksR.dir/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/anti_shadowsocksR.dir/main.cpp.o -c /root/anti-shadowsocksR/main.cpp

CMakeFiles/anti_shadowsocksR.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/anti_shadowsocksR.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/anti-shadowsocksR/main.cpp > CMakeFiles/anti_shadowsocksR.dir/main.cpp.i

CMakeFiles/anti_shadowsocksR.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/anti_shadowsocksR.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/anti-shadowsocksR/main.cpp -o CMakeFiles/anti_shadowsocksR.dir/main.cpp.s

# Object files for target anti_shadowsocksR
anti_shadowsocksR_OBJECTS = \
"CMakeFiles/anti_shadowsocksR.dir/main.cpp.o"

# External object files for target anti_shadowsocksR
anti_shadowsocksR_EXTERNAL_OBJECTS =

anti_shadowsocksR: CMakeFiles/anti_shadowsocksR.dir/main.cpp.o
anti_shadowsocksR: CMakeFiles/anti_shadowsocksR.dir/build.make
anti_shadowsocksR: CMakeFiles/anti_shadowsocksR.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/anti-shadowsocksR/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable anti_shadowsocksR"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/anti_shadowsocksR.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/anti_shadowsocksR.dir/build: anti_shadowsocksR

.PHONY : CMakeFiles/anti_shadowsocksR.dir/build

CMakeFiles/anti_shadowsocksR.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/anti_shadowsocksR.dir/cmake_clean.cmake
.PHONY : CMakeFiles/anti_shadowsocksR.dir/clean

CMakeFiles/anti_shadowsocksR.dir/depend:
	cd /root/anti-shadowsocksR/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/anti-shadowsocksR /root/anti-shadowsocksR /root/anti-shadowsocksR/cmake-build-debug /root/anti-shadowsocksR/cmake-build-debug /root/anti-shadowsocksR/cmake-build-debug/CMakeFiles/anti_shadowsocksR.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/anti_shadowsocksR.dir/depend

