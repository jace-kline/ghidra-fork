import psutil

def main():
    kills = []

    # Ghidra parent process is assumed to be the most recent "java" process running
    javas = [ p for p in psutil.process_iter() if p.name() == "java" ]
    if len(javas) > 1:
        kills.append(javas[-1])

    # Ghidra decompiler process(es) are identified by name "decompile"
    decompiles = [ p for p in psutil.process_iter() if p.name() == "decompile" ]
    kills += decompiles

    for p in kills:
        print(f"killing process {p.pid} - {p.name()}")
        try:
            p.kill()
        except:
            pass

if __name__ == "__main__":
    main()