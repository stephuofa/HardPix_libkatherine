param(
    [switch]$clean
)

if($clean){
    rm -r build
    mkdir build
}

cd build
cmake .. -G "Visual Studio 16 2019" -A Win32
cd ..
cmake --build build
