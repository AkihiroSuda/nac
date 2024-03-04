package run

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/log"
	"github.com/spf13/cobra"
)

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>

int call_execvp(void *p, const char *file, char *const argv[]) {
  int (*fn_execvp)(const char *file, char *const argv[]) = p;
	return fn_execvp(file, argv);
}
*/
import "C"

const Example = `  # Virtually mount /tmp/usr_local into /usr/local
  nac run -it --rm -v $HOME/usr_local:/usr/local host bash
`

// HostImage is the dummy image that represents the host.
const HostImage = "host"

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "run [OPTIONS] host COMMAND [ARG...]",
		Short:   "Run a non-container",
		Example: Example,
		Args:    cobra.MinimumNArgs(2),
		RunE:    action,

		DisableFlagsInUseLine: true,
	}

	flags := cmd.Flags()
	flags.SetInterspersed(false)
	flags.BoolP("interactive", "i", false, "Dummy flag for consistency with `docker run -i`")
	flags.BoolP("tty", "t", false, "Dummy flag for consistency with `docker run -t`")
	flags.Bool("rm", false, "Dummy flag for consistency with `docker run --rm`")
	flags.StringArrayP("volume", "v", nil, "Bind mount a volume")
	return cmd
}

func action(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	flagI, err := flags.GetBool("interactive")
	if err != nil {
		return err
	}
	if !flagI {
		return errors.New("flag `-i` has to be always specified currently")
	}

	flagT, err := flags.GetBool("tty")
	if err != nil {
		return err
	}
	if !flagT {
		return errors.New("flag `-t` has to be always specified currently")
	}

	flagRM, err := flags.GetBool("rm")
	if err != nil {
		return err
	}
	if !flagRM {
		return errors.New("flag `--rm` has to be always specified currently")
	}

	flagV, err := flags.GetStringArray("volume")
	if err != nil {
		return err
	}
	nacRedirects, err := parseFlagV(flagV)
	if err != nil {
		return err
	}
	os.Setenv("_NAC_REDIRECTS", nacRedirects)

	imageRef, userCmd, userCmdArgs := args[0], args[1], args[2:]
	if imageRef != HostImage {
		return fmt.Errorf("expected virtual image %q, got %q", HostImage, imageRef)
	}

	nacStateDir, err := os.MkdirTemp("", "nac-*")
	if err != nil {
		return err
	}
	nacStateDir, err = realpath(nacStateDir)
	if err != nil {
		return err
	}
	log.L.Debugf("state dir: %q", nacStateDir)
	// TODO: clean up state dir
	os.Setenv("_NAC_STATE_DIR", nacStateDir)

	libnac, err := libnacPath()
	if err != nil {
		return fmt.Errorf("failed to find libnac: %w", err)
	}
	if _, err := os.Stat(libnac); err != nil {
		return err
	}
	os.Setenv("DYLD_INSERT_LIBRARIES", libnac)

	dl := C.dlopen(C.CString(libnac), C.RTLD_LAZY)
	if dl == nil {
		return fmt.Errorf("failed to call dlopen(%q, RTLD_LAZY)", libnac)
	}
	const execvpSym = "execvp"
	execvp := C.dlsym(dl, C.CString(execvpSym))
	if execvp == nil {
		return fmt.Errorf("failed to find %q in %q", execvpSym, libnac)
	}

	if !strings.HasSuffix(userCmd, "sh") {
		// FIXME
		log.L.Warnf("expected a shell like \"bash\", got %q (may not work)", userCmd)
	}

	if log.GetLevel() >= log.DebugLevel {
		os.Setenv("_NAC_DEBUG", "1")
	}

	_, err = C.call_execvp(execvp, C.CString(userCmd),
		cStringSlice(append([]string{userCmd}, userCmdArgs...)))
	return err
}

func libnacPath() (string, error) {
	selfExe, err := os.Executable() // "/usr/local/bin/nac"
	if err != nil {
		return "", err
	}
	binDir := filepath.Dir(selfExe)                 // "/usr/local/bin"
	localDir := filepath.Dir(binDir)                // "/usr/local"
	libDir := filepath.Join(localDir, "lib")        // "/usr/local/lib"
	libnac := filepath.Join(libDir, "libnac.dylib") // "/usr/local/lib/libnac.dylib"
	return libnac, nil
}

func realpath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

func parseFlagV(ss []string) (string, error) {
	var res string
	for i, s := range ss {
		x, err := parseFlagVSingle(s)
		if err != nil {
			return "", fmt.Errorf("failed to parse %q: %w", s, err)
		}
		res += x
		if i != len(ss)-1 {
			res += ":"
		}
	}
	return res, nil
}

func parseFlagVSingle(s string) (string, error) {
	sp := strings.SplitN(s, ":", 2)
	if len(sp) != 2 {
		return "", fmt.Errorf("expected `<SRC>:<DST>`, got %q", s)
	}
	src, dst := sp[0], sp[1]
	srcReal, err := realpath(src)
	if err != nil {
		return "", err
	}
	return dst + "=" + srcReal, nil
}

func cStringSlice(ss []string) **C.char {
	x := make([]*C.char, len(ss)+1)
	for i, s := range ss {
		cs := C.CString(s)
		x[i] = cs
	}
	return &x[0]
}
