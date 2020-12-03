package cmd

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "go-mitm",
	Short: "A man-in-the-middle http proxy server",
	Long: `go-mitm is a proxy server which is able to read transmitted data
in SSL/TLS connection using man-in-the-middle technique.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
