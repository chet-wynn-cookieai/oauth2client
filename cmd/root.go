package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	RootCmd.PersistentFlags().CountP("verbose", "v", "verbose: once for debug; twice (vv) for trace")
}

var RootCmd = &cobra.Command{
	Use:     "oauth2client",
	Aliases: []string{"oauth2client"},
	Short:   "OAuth2 client test tool",
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		count, _ := cmd.Flags().GetCount("verbose")
		switch count {
		case 1:
			log.SetLevel(log.DebugLevel)
		case 2:
			log.SetLevel(log.TraceLevel)
		}
	},
}
