This is `punchdebug`, a tool for force-loading modules with a wrong vermagic
even on kernels without `CONFIG_MODULE_FORCE_LOAD`. Because root should be able
to mess up his kernel as much as he wants to, that's why. Also because android
app developers might want to avoid compiling a module for all the kernels out
there.

== LICENSE ==
Copyright (C) 2012 Jann Horn <jannhorn@googlemail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

== How it works ==
Normal force-loading just removes the vermagic, which leaves the decision
about whether force-loading is ok to the kernel. However, it's also possible
to spoof the vermagic, making the kernel thing the module's vermagic is ok.
That's what this program does.

As we need to determine the needed vermagic anyway, we first make a polite request,
asking the kernel to load the module. But if the kernel doesn't want to, we punch
the module into the kernel. :)

== Limitations ==
This program can't make incompatible code compatible, it can just make the kernel
think it's compatible. If the code is actually incompatible, your machine might
explode or something like that. You've been warned!
