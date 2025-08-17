# Autopwn

![Sample usage](
  assets/usage.png
)

Autopwn is a tool for automatically exploiting vulnerable binaries.
It uses [angr](https://github.com/angr/angr/) to solve for inputs and to analyse program states, [radare2](github.com/radareorg/radare2) for disassembly, [pwntools](https://github.com/Gallopsled/pwntools) for executing exploits, and NO AI!!!

### Capabilities

Autopwn is able to
- identify win functions used in ctf challenges,
- utilise stack buffer overflows to jump to arbitrary locations,
- utilise controlled printf format strings leak canaries and relative addresses to bypass stack sanitisation and PIE,
- solve for inputs satisfying constraints e.g. passwords,
- perform ROP chains to call `system` in order to spawn a shell,
- interact with remotes,

### Ctfs

Autopwn has been used to automatically solve already existing ctf challenges:
- list


### Future work
As this was a hackathon project, we weren't able to implement all of the functionality we wanted to.
In the future we intend to rearchitect the codebase to make adding new vulnerabilities as streamlined as possible, as well as having exploits be as composable as possible.
