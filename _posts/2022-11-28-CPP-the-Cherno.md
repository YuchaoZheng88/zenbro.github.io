---
title: C++ The Cherno
author: Yuchao
date: 2022-11-28 11:33:00 +0800
categories: [dev]
tags: [c++]
math: true
mermaid: true
---

From cherno C++
- https://www.youtube.com/playlist?list=PLlrATfBNZ98dudnM48yfGUldqGD0S4FFb/

e5
- Project Configuration -> Configuration type -> .exe/ .dll/ .lib
- C++ -> Optimization -> Disabled(debug mode) / Max Optimization(release mode)
- code compile to .obj file, linker them to .exe
- VS error list is garbage. Use Output window.
- Declaration VS Definition. Linker wiil find wrong declaration without definition when build the project.

e6 compiler
- file name has no meaning, unlike java, just feed to compiler as .cpp or .h 
- include cpp files, after compiling, just one .obj file. They are one translation unit.
- EndBrace.h file only contain ‘}’, in a.cpp, #include “EndBrace.h”, will behave same as a ‘}’
- Configuration -> C/C++ -> Preprocessor -> to a file “Yes”. can check .i file which is pre codes. This option suppresses producing .obj file.
- #if 0, #endif, preprocessor will fade out the codes between them.
- check #include <iostream> from .i file, we see iostream codes before our code for 50610 lines.
- Configuration -> C/C++ -> Output Files -> Assembler Output. We can see .obj as assembly codes in .asm file.

e7 linker
- if compile to .exe, linker will check entry point, main function existence.
- file log.h has a static function, when included by other .cpp files, like different version of the function. waste & ugly.
- file log.h has a non-static function, when included by other .cpp files, cause link error as multiply defined.
- static: variable/function cannot be used in other translation units.

e8
- int, 4 byte， -2 to 2 billion
- char 1-byte, short 2-byte, long 4-byte, long long 8-byte.
- float 4-byte, double 8-byte

e9

e10
- Java, C# do not have header files.
- #include, #pragma, etc. are preprocess command. do before compile.
- #pragma once. In case copy the header file multiple times to one translation unit (not the whole program).
- gcc clang msvc, all support #pragma once.
- header file in C standard library like stdlib.h; in CPP standard library like iostream, no extension .h

e11 debug
- windows -> debug -> memory - memory 1
- Address: &a. check what in a`s memory address.
- In debug mode, non initialized variables will be filled with “cc cc cc cc”.

e12 if
- debug at break point, right click -> Go To Disassembly.
- if(a) in assembly, test eax(a), eax(a); je [out of if block]; if block code. Same as if(a==0) not ifcode, else ifcode

e13 vs setup
- config macro check. little arrow -> edit -> Macros.

e14

e15
- continue, go to next loop; break, go out of entire loop; return, return function.

e16 pointer
```c++
char* buffer = new char[8];  // on heap
memset(buffer, 0, 8);

char** ptr = &buffer;
delete[] buffer;
```

e17 reference
```c++
int a = 5;
int& ref = a;
// ref and a are same thing, same address, like another name of a.

void IncrementRef(int& value) {
    value++;
} 
// value is a reference of the parameter, so the parameter can be increased, out of the function.
// less code than below.

void IncrementPointer(int* value) {
    (*value)++;  // dereference the pointer first, then increase the value.
} 
// increase the value of the pointer, same effect as using reference.

```

e18/19/21  class structs
- function in class named method.
- class default private, struct default public. Only difference.

e22 static
- static in class/struct, only one place of memory, for all the objects to use.
- extern keyword, look the variable/function from other translation units. But not for static variable/function in other translation units.
- private to class -> static to translation unit.
- try static first, then global.

e23 enum

e24 constructor
- private constructor (overload) prevent users to use class in an unwanted way.
- class Log. in public: Log() = delete; also prevent this way of construct class.

e25 destrutor
- manually call may lead to call twice, if doing with memory, not good.

e26 inheritance
- ``` class Player : public Entity {}; ```
- public inheritance makes public members of the base class public in the derived class, and the protected members of the base class remain protected in the derived class.
- protected inheritance: protected.
- private inheritance : private.

e27 virtual function
- Entity* e = new Entity(); // new return the address on heap.
- player : entity. pointer to player -> function, will call entiry.function().
- ``` Parent* p = new Child(); p->testFunc();``` without ‘virtual’, will call parent`s function.
- virtual method table (VMT). ‘virtual’ before function name. call right derived class function.
- in subclass, mark overwritten function ‘override’.
- a little cost, someone may not use virtual function.

e28 pure virtual
- pure virtual function is specified by placing "= 0" in its declaration.
- ``` virtual double getVolume() = 0;  ``` it is interface.

e29
- private, protected, public

e30 array
- read memory not array, in debug mode may cruch, in release mode may just read.
- int* int_ptr = array; *(int_ptr + 2) = 6; // same as array[2] = 6; // int array just a int pointer.
- *(int *)((char*)int_ptr + 8) = 6; // same as *(int_ptr + 2) = 6; 8 one-byte equals 2 4-byte
- ``` int* another = new int[5]; delete[] another; ``` delete an array on heap.
- ``` int* ptr1 = new int; int* ptr2 = new int(20); delete ptr1; delete ptr2 ``` delete pointer, compare delete array
- delete is used for one single pointer and delete[] is used for deleting an array through a pointer.
- int* a=new int[5]; int b[5]; sizeof(a) = 4/8(32/64bit compile) ; sizeof(b) = 20. // pointer to heap/stack array size difference.
- type a is int*; type b is int*[5]
- static const int num = 5; int a[num] // must be static const.
- ``` #include <array>  std::array<int, 5> onearray; ``` // this standard array, before is raw array

e31 string
- char abb[4] = {'a','a', 'a', 0};  char abb[4] = {'a','a', 'a', '/0'};
- char abb[4] = "ABC";
- #include <string>
- void PString(const std::string& str) {} // const: not modify, &: not make a new copy of string.

e32 
- const char* name = "abc";
- const wchar_t* name2 = L"abcdasdf"; // 2 byte for a char
- const char16_t* name3 = u"asdf"; // 2 byte
- const char32_t* name4 = U"pvawe"; // 4 byte
```c++
const char* aa = R"(wef
fewef
fwef
fwef)"; // change line easily, R means raw.
```

e33 const
- const int* a = new int;  //  a=(int *)&anotherInt   is good     ;   *a = 2   cannot do. cant change content
- const int *a, same as, int const* a
- int* const a = new int;  //  a=(int *)&anotherInt   cannot do ;   *a = 2   is good    . cant change address
- const before/after *
- const int* const a = new int // cannot change content and address
- in class public function, int GetX() const. const function will not change class. Like Read Only.
- void function(const EntityClass& e){} // can only call const function of the class.
- mutable int a; // in class, can be modified in const function.

e34 mutable
- auto f = [=](){}; // lambda function, = pass all variable by value, & all by reference
```c++
int x = 8;
auto f = [=]() mutable
{
	x++;
	std::cout<<x;
} // pass by value can used right away; or int y=x, then use y
f();
// just another usecase of mutable, 99% just in const function of class, not this.
```

e35 
- initialize class.
- Entity() : m_Name("Unknown"), m_Score(0) {}        // same as below
- Entity() { m_Name = "Unknown"; m_Score = 0; }    // same as above
- Entity(const std::string& name) : m_Name(name) {} // another example

e36 Ternary 
- Speed = Level > 5 ? 10 : 5;

e37
- using namespace std; // is not not not recommended.
- Entity* entity = new Entity();
- entity->function(); or (*entiry).function(); // pointer -> , dereference .

e38 new
- new on heap
- right click ‘new’ -> go to definition. new is an operator.
- void* __CRTDECL operator new(size_t _Size);
- Entity* e = new Entiry();                              // same as below, but call constructor.
- Entity* e = (Entity*)malloc(sizeof(Entity));   // same as above, but not call constructor.
- delete e; // when use new, must delete.
- Entity* e = new(ptr) Entiry(); // new to a specific pointer.

e39
- explicit constructor, stricter rule

e40 operator overloading
```c++
Vector2 operator+(const Vector2& other) const{
	return Vector2(x+other.x, y+other.y);
}// overload + 

Verctor2 Add(const Vector2& other) const{
	return *this + other; 
}// this is a pointer to the object, *this is Vector2

Verctor2 Add(const Vector2& other) const{
	return operator+(other);
} // same as above, but werid.
```

overload std::cout to print class Vector2
```c++
std::ostream& operator<<(std::ostream& stream, cont Vector2& other){
	stream << other.x << ", " << other.y;
	return stream;
}
```

e41 this
- pointer to the current object instance that the method(non-static) belongs to.

e42
- allocate object on stack, will destroy when code out of scope. On heap, it is not.
```c++
class ScopedPtr{
private:
	Entity* m_Ptr;
public:
	ScopedPtr(Entity* ptr): m_Ptr(ptr) {}
	
	~ScopedPtr() { delete m_Ptr; }
}

int main() {
	{ ScopedPtr e = new Entity(); }
}

// new on heap will not auto free memory when out of scope, 
// but with ScopedPtr, the pointer on stack will free the memory on heap by its destructor.
```

e42 smart pointer
- call new on heap, do not need to delete.
- wrapper around a raw pointer.
- can not copy a unique pointer, one auto delete will affect the other.
```c++
#include <memory>
{
	{ std::unique_ptr<Entity> entity = std::make_unique<Entity>(); } // best safe way 
	// { std::unique_ptr<Entity> entity(new Entitry()); }  another way to initialize.
	// can not use = new Entitry(); to initialize, because explicit keywork in unique_ptr.
	// entity will be destroyed when out of scope.
}

//in unique_ptr classs
unique_ptr(const unique_ptr&)            = delete;
unique_ptr& operator=(const unique_ptr&) = delete;
// in case copy a unique pointer.
```

shared pointer
- std::unique_ptr, std::shared_ptr, std::weak_ptr
- need reference counter, count how many instances have created.
- memory freed when last pointer dies.
```c++
int main(){
	{	
	std::shared_ptr<Entity> e0;
		{
			std::shared_ptr<Entiry> sharedEntity = std::make_shared<Entity>();
			e0 = sharedEntiry; 
		}  // heap not freed here. e0 still exists.
	} // heap freed here, e0 out of scope.
}
```

weak pointer
- do not count the instances, act as an observer, use after asking if exists.
```c++
std::weak_ptr<int> gw;
gw.use_count();
if (std::shared_ptr<int> spt = gw.lock()) {} // no object, lock return empty, so false
if (gw.expired()) {} // Equivalent to use_count() == 0
```

e44
```c++
class String{
private:
	char* m_Buffer;
	unsigned int m_Size;
public:
	String(const char* string){
		m_Size = strlen(string);
		m_Buffer = new char[m_Size+1]; // 1 for null termination character.
		memcpy(m_Buffer, string, m_Size); // m_Size in bytes.
		m_Buffer[m_Size] = 0;
	}
	
	~String(){
		delete[] m_Buffer;	
	}
	
	friend std::ostream& operator<<(std::ostream& stream, const String& string);
	// this allow ostream << operator to get String class private value m_Buffer.
};

std::ostream& operator<<(std::ostream& stream, const String& string){
	stream << string.m_Buffer;
	return stream;
}

int main(){
	String a = "abc";
	String b = a;
	// a is a reference, b just copied all variable from a. shallow copy.
	// copy int value and memory address.
	// end of scope, it will destruct twice, cause program to crash.
}
```

copy constructor
```c++
String(const String& other)
{
	m_Buffer = new char[m_Size + 1];
	memcoy(this, &other, sizeof(other)); //deep copy
	// *this.buffer = other.buffer; *this.size=other.size shallow copy
}
// default will be shallow copy.
// make your version of how to copy.
```

e45
```c++
int offset = (int)&((Vector3*)nullptr)->y;
// check offset of a class.
```

e46 std::vector
- dynamic array. opposite to raw array, size fixed.
```c++
#include <vector>

std::vector<MyStruct> mystruct;
mystruct.push_back({1,2,3}); // {1,2,3} initialize a new mystruct.
int i = mystruct.size();
```

e47 vector push_back copy times
- test how many times a class has been copied.
- log in copy constructor.
```c++
std::vector<Vertex> vertices;
vertices.push_back(Vertex(1,2,3)); // copy *1, total 1. copy from main stack, to heap.
vertices.push_back(Vertex(4,5,6)); // copy *2, total 3. resize, then on heap.
vertices.push_back(Vertex(7,8,9)); // copy *3, total 6. resize, then on heap.

vertices.reserve(3); // use before push_back
```
- ALWAYS try to reserve before you start pushing back elements into the container.
```c++
// no single copy version
std::vector<Vertex> vertices;
vertices.reserve(3);
vertices.emplace_back(1,2,3);
vertices.emplace_back(4,5,6);
vertices.emplace_back(7,8,9);
// total 0 copy !!!
```

e48 static in scope
```c++
void function(){
	static int i = 0;
	i++;  
	std::cout << i << std::endl;
}
// output: 1,2,3,.....
```
singleton by static, easy and clean
```c++
class Singleton(){
public:
	static Singleton& get(){
		static Singleton instance; // first time will create it on stack, later will not.
		return instance;	
	}
};
```

e49
- glfw3.dll   dynamic library.  glfw3dll.lib  static library use with .dll. link at compile time.
- glfw3.lib   static library
- config -> c/c++ -> Genral -> Additional Include Directories.  for header.
- config -> Linker -> Input -> Additional Dependencies.  for lib file name.
- config -> Linker -> General -> Additional Library Directories. for lib path.

```c++
extern "C" int glfwInit(); 
// glfw is a C library, without extern “C” will mangling the name with C++.
// preserve the name even though it is in C.
```

e50 dll
- use when should use. runtime.
- config -> Linker -> Input -> Additional Dependencies.  add glfw3dll.lib. this help find .dll function address.
- complie and run. get error. can not find glfw3.dll.
- simple way: copy .dll to .exe, in same path.
```c++
/* GLFWAPI is used to declare public API functions for export
 * from the DLL / shared library / dynamic library.
 */
#if defined(_WIN32) && defined(_GLFW_BUILD_DLL)
 /* We are building GLFW as a Win32 DLL */
 #define GLFWAPI __declspec(dllexport)
#elif defined(_WIN32) && defined(GLFW_DLL)
 /* We are calling a GLFW Win32 DLL */
 #define GLFWAPI __declspec(dllimport)
#elif defined(__GNUC__) && defined(_GLFW_BUILD_DLL)
 /* We are building GLFW as a Unix shared library */
 #define GLFWAPI __attribute__((visibility("default")))
#else
 #define GLFWAPI
#endif
```

e51
- more projects in one solution.
- right click one project -> add -> reference -> another project.
- complie A and B, if A rely on B.

e52
- function parsing pointer than reference, good thing is null can be parsed.
- array, vector difference. Just assign value(without new): array data on stack, vector data on heap.
- tuple, struct.

e53 templates
- compiler write code for you.
```c++
template<typename T>
void function(T value){ // do somethin.}
function(5);
function("afsdf");

// if define class name
template<class T>
function<int>(5);
function<std::string>("aasdf");
```
- If not call templeta function, compiler will ignore it, even with sytax error.
- template only create code when we use the function.
```c++
template<typename T, int N>

class Array{
private:
	T m_Array[N];
public:
	int GetSize() const {return N;}
};

// in main
Array<int, 5> array;
// in compile time, the array class will be coded as m_Array[5]
```

e54
- new allocate on heap.
- delete value, delete[] array; after using new.
- new will call malloc function, which ask free list, for free memory to allocate.
- allocate on stack is one CPU instruction; while on heap, a series of instructions. 
- stack: mov DWORD PTR _value$[ebp], 5 ; one instruction

e55 macro
- find and replace
- #define WAIT std::cin.get()
- debug mode need more logs.
- Indebug mode: C/C++ -> Preprocessor -> Preprocessor Definitions: add PR_DEBUG in the list.
- same as above in release mode, add PR_RELEASE.
```c++
#ifdef PR_DEBUG
#define LOG(x) std::cout << x << std::endl
#elif defined(PR_RELEASE)
#define LOG(x)
#endif

// if in debug mode, LOG(x) will print; in other mode, LOG(x) do nothing

// another way
#define PR_DEBUG 1
#if PR_DEBUG == 1
// same as above, maybe a little bit clear

// like comment out all macro, see below
#if 0
// all the marco you want to comment out here.
#endif
```

e58/59 function pointer, lambda
```c++
void fun(int a){}

void (*fun_ptr)(int) = &fun;

auto x1 = [](int i){ return i; }; // lambda
```

e62 threads
```c++
#include <thread>

void DoWork() {
	using namespace std::literals::chrono_literals;  // use 1s later
	std::cout << std::this_thread::get_id();   // print thread ID.
	std::this_thread::sleep_for(1s);   		 	 // sleep for 1 second.
}

int main(){
	std::thread worker(DoWork);
	work.join(); // main thread wait for worker thread to finish.
}
```

e63
```c++
#include <chrono>

auto start = std::chrono::high_resolution_clock::now();
std::chrono::duration<float> duration = end - start;
std::cout << duration.count();

////////////////////////////////////

struct Timer{
	std::chrono::time_point<std::chrono::steady_clock> start,end;
	std::chrono::duration<float> duration;
	
	Timer(){
		start = std::chrono::high_resolution_clock::now();	
	}
	
	~Timer(){
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		float ms = duration.count() * 1000.0f;
		std::cout << Timer took << ms << "ms" << std::endl;	
	}
};

// test the run time of code block, just put 
// Timer timer;
// in the beginning of the code block.
```

e65 sorting
```c++
std::vector<int> values = {1,3,4,6,5};
std::sort(values.begin(), values,end(), [](int a, int b){
	return a<b;
});
```

e66 type punning
```c++
Entity e = {5, 8};
int* position = (int*)&e;
int y = *(int*)((char*)&e+4);  // 4 char is 4 byte, to the next int y, then dereference.
```
