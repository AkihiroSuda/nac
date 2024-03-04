package main

import (
	"github.com/AkihiroSuda/nac/cmd/nac/commands/run"
	"github.com/containerd/log"
	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		log.L.Fatal(err)
	}
}

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "nac",
		Short:         "NAC is Not A Container",
		Example:       run.Example,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	flags := cmd.PersistentFlags()
	flags.Bool("debug", false, "debug mode")

	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if debug, _ := cmd.Flags().GetBool("debug"); debug {
			if err := log.SetLevel(log.DebugLevel.String()); err != nil {
				log.L.WithError(err).Warn("Failed to enable debug logs")
			}
		}
		return nil
	}

	cmd.AddCommand(
		run.NewCommand(),
	)
	return cmd
}
