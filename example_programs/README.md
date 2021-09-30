# Example Programs

The programs included here are examples to help others build their own programs.  While they have been tested
in test environment, they have not been vetted or tested in production capacity.

I very highly recommend going through the *excellent* tutorial https://github.com/xdp-project/xdp-tutorial, following
the lessons for least Basic 1-4, and Packet 1.

The examples here use parsing helpers and a common Makefile from the xdp-tutorial project. The xdp-tutorial project is
included as a submodule for convenience.

If you want to build these programs, clone this repo with the following options:

```
git clone --recurse-submodules https://github.com/chrisohaver/ebpf
```

Or, if you have already cloned without submodules, you can do this after the fact with:

```
git submodule update --init --recursive
```

