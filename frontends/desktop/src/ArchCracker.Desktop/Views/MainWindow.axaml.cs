// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using ArchCracker.Desktop.ViewModels;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;

namespace ArchCracker.Desktop.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        AddHandler(DragDrop.DragOverEvent, OnDragOver);
        AddHandler(DragDrop.DropEvent, OnDrop);
    }

    private void OnDragOver(object? sender, DragEventArgs e)
    {
        e.DragEffects = DragDropEffects.Copy;
        e.Handled = true;
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (DataContext is MainWindowViewModel vm)
        {
            if (e.KeyModifiers.HasFlag(KeyModifiers.Control) && e.Key == Key.O)
            {
                vm.BrowseArchiveCommand.Execute(null);
                e.Handled = true;
            }
            else if (e.Key == Key.F5)
            {
                vm.StartCommand.Execute(null);
                e.Handled = true;
            }
            else if (e.Key == Key.Escape)
            {
                vm.StopCommand.Execute(null);
                e.Handled = true;
            }
        }
        base.OnKeyDown(e);
    }

    private void OnDrop(object? sender, DragEventArgs e)
    {
        if (DataContext is not MainWindowViewModel vm) return;
        var path = e.DataTransfer.TryGetFiles()?.FirstOrDefault()?.TryGetLocalPath();
        if (!string.IsNullOrWhiteSpace(path))
        {
            vm.SetArchivePath(path);
            e.Handled = true;
        }
    }
}
