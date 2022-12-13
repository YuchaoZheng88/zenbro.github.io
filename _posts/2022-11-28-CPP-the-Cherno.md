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

// new on heap will not free memory when outof scope, 
// but with ScopedPtr, the pointer on stack will free the memory on heap.
```
