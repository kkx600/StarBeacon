package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kkx600/StarBeacon/internal/app"
	"github.com/kkx600/StarBeacon/internal/collectorupdate"
)

func maintenance(args []string) (bool, error) {
	if len(args) == 0 || args[0] != "maintenance" && args[0] != "maintenance-probe" && args[0] != "maintenance-boot" && args[0] != "maintenance-run" {
		return false, nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if args[0] == "maintenance" {
		return true, collectorupdate.CLI(ctx, args[1:], os.Stdout, os.Stderr)
	}
	flags := flag.NewFlagSet("maintenance-probe", flag.ContinueOnError)
	address := flags.String("url", "", "本机就绪地址")
	ca := flags.String("ca", "", "就绪服务 CA")
	root := flags.String("root", "", "维护目录")
	binary := flags.String("binary", "", "容器固定程序")
	uid := flags.Int("uid", 0, "服务用户")
	gid := flags.Int("gid", 0, "服务组")
	if err := flags.Parse(args[1:]); err != nil {
		return true, err
	}
	if flags.NArg() != 0 {
		return true, fmt.Errorf("就绪探测不接受额外位置参数")
	}
	switch args[0] {
	case "maintenance-boot":
		return true, collectorupdate.BootGuard(*root)
	case "maintenance-run":
		return true, collectorupdate.ExecManaged(*root, *binary, *uid, *gid)
	default:
		if *ca == "" {
			return true, collectorupdate.Probe(ctx, *address)
		}
		return true, collectorupdate.Probe(ctx, *address, *ca)
	}
}

func main() {
	if handled, err := maintenance(os.Args[1:]); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "采集器维护未完成：", err)
			os.Exit(1)
		}
		return
	}
	app.Main("agent")
}
